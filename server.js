import { Hono } from 'jsr:@hono/hono';
import { serveStatic } from 'jsr:@hono/hono/deno';
import { jwt, sign } from 'jsr:@hono/hono/jwt';
import { setCookie, deleteCookie, getCookie } from 'jsr:@hono/hono/cookie';
import { hash, verify } from 'jsr:@felix/bcrypt';

const JWT_SECRET = Deno.env.get('JWT_SECRET') || 'your-secret-key';
const COOKIE_NAME = 'auth_token';

// --- 追加：有効期限（1日分 = 60秒 * 60分 * 24時間） ---
const EXP_TIME = 60 * 60 * 24;

const app = new Hono();
const kv = await Deno.openKv();

// --- ユーザー認証 ---
app.post('/api/signup', async (c) => {
  const { username, password } = await c.req.json();
  const userExists = await kv.get(['users', username]);
  if (userExists.value) return c.json({ message: '使用済み' }, 409);
  const hashedPassword = await hash(password);
  await kv.set(['users', username], { username, hashedPassword });
  return c.json({ message: '成功' }, 201);
});

app.post('/api/login', async (c) => {
  const { username, password } = await c.req.json();
  const userEntry = await kv.get(['users', username]);
  const user = userEntry.value;

  if (!user || !(await verify(password, user.hashedPassword))) {
    return c.json({ message: '無効' }, 401);
  }

  // payloadの中のexpに期限を設定
  const payload = {
    sub: user.username,
    exp: Math.floor(Date.now() / 1000) + EXP_TIME
  };

  const token = await sign(payload, JWT_SECRET);

  // Cookie自体の期限(maxAge)にも同じ期限を設定
  setCookie(c, COOKIE_NAME, token, {
    path: '/',
    httpOnly: true,
    sameSite: 'Strict',
    maxAge: EXP_TIME // これで500エラーが消えます
  });

  return c.json({ message: 'ログイン成功', username: user.username });
});

app.use('/api/*', jwt({ secret: JWT_SECRET, cookie: COOKIE_NAME }));

app.get('/api/check', (c) => c.json({ username: c.get('jwtPayload').sub }));
app.post('/api/logout', (c) => {
  deleteCookie(c, COOKIE_NAME);
  return c.body(null, 204);
});

// --- 投稿・お気に入りロジック ---
app.post('/api/colors', async (c) => {
  const username = c.get('jwtPayload').sub;
  const body = await c.req.parseBody();
  const record = JSON.parse(body['record']);
  record.author = username;
  record.createdAt = new Date().toISOString();
  const id = Date.now().toString(); // ユニークID
  record.id = id;
  await kv.set(['colors', id], record);
  return c.json({ record });
});

app.get('/api/colors', async (c) => {
  const username = c.get('jwtPayload').sub;
  const list = await kv.list({ prefix: ['colors'] });
  const records = [];
  for await (const entry of list) {
    const fav = await kv.get(['favorites', username, entry.value.id]);
    entry.value.isFavorite = !!fav.value; // お気に入り済みか判定
    records.push(entry.value);
  }
  return c.json(records.reverse());
});

// お気に入り切り替え
app.post('/api/favorites/:id', async (c) => {
  const username = c.get('jwtPayload').sub;
  const id = c.req.param('id');
  const key = ['favorites', username, id];
  const existing = await kv.get(key);
  if (existing.value) {
    await kv.delete(key);
    return c.json({ favorite: false });
  } else {
    await kv.set(key, true);
    return c.json({ favorite: true });
  }
});

// マイページ用データ取得
app.get('/api/me', async (c) => {
  const username = c.get('jwtPayload').sub;
  const allList = await kv.list({ prefix: ['colors'] });
  const myPosts = [];
  const myFavorites = [];
  const favIds = new Set();
  const favList = await kv.list({ prefix: ['favorites', username] });
  for await (const f of favList) favIds.add(f.key[2]);
  for await (const entry of allList) {
    if (entry.value.author === username) myPosts.push(entry.value);
    if (favIds.has(entry.value.id)) myFavorites.push(entry.value);
  }
  return c.json({ myPosts, myFavorites });
});

app.on('GET', ['/signup.html', '/login.html'], async (c, next) => {
  if (getCookie(c, COOKIE_NAME)) return c.redirect('/index.html');
  await next();
});

app.get('/*', serveStatic({ root: './public' }));
Deno.serve(app.fetch);
