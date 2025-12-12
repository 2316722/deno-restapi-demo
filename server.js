import { Hono } from 'jsr:@hono/hono';
import { serveStatic } from 'jsr:@hono/hono/deno';

// 認証トークン（JWT）
import { jwt, sign } from 'jsr:@hono/hono/jwt';

// クッキー
import { setCookie, deleteCookie, getCookie } from 'jsr:@hono/hono/cookie';

// パスワードのハッシュ化（bcrypt）
import { hash, verify } from 'jsr:@felix/bcrypt';

// サーバーの秘密鍵
const JWT_SECRET = Deno.env.get('JWT_SECRET');

// JWT用のクッキーの名前
const COOKIE_NAME = 'auth_token';

const app = new Hono();
const kv = await Deno.openKv();

/*
 * ---------------------
 * ユーザー認証エリア (変更なし)
 * ---------------------
 */

/*** ユーザー登録 ***/
app.post('/api/signup', async (c) => {
  const { username, password } = await c.req.json();
  if (!username || !password) {
    c.status(400);
    return c.json({ message: 'ユーザー名とパスワードは必須です' });
  }

  const userExists = await kv.get(['users', username]);
  if (userExists.value) {
    c.status(409);
    return c.json({ message: 'このユーザー名は既に使用されています' });
  }

  const hashedPassword = await hash(password);
  const user = { username, hashedPassword };
  await kv.set(['users', username], user);

  c.status(201);
  return c.json({ message: 'ユーザー登録が成功しました' });
});

/*** ログイン ***/
app.post('/api/login', async (c) => {
  const { username, password } = await c.req.json();
  const userEntry = await kv.get(['users', username]);
  const user = userEntry.value;

  if (!user) {
    c.status(401);
    return c.json({ message: 'ユーザー名が無効です' });
  }

  if (!(await verify(password, user.hashedPassword))) {
    c.status(401);
    return c.json({ message: 'パスワードが無効です' });
  }

  const payload = {
    sub: user.username,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 // 24時間有効
  };

  const token = await sign(payload, JWT_SECRET);

  setCookie(c, COOKIE_NAME, token, {
    path: '/',
    httpOnly: true,
    secure: false, // 本番環境ではtrue
    sameSite: 'Strict',
    maxAge: 60 * 60 * 24
  });

  return c.json({ message: 'ログイン成功', username: user.username });
});

/* 上記以外の /api 以下へのアクセスにはログインが必要 */
app.use('/api/*', jwt({ secret: JWT_SECRET, cookie: COOKIE_NAME }));

/*** ログアウト ***/
app.post('/api/logout', (c) => {
  deleteCookie(c, COOKIE_NAME, {
    path: '/',
    httpOnly: true,
    secure: false,
    sameSite: 'Strict'
  });
  c.status(204);
  return c.body(null);
});

/*** ログインチェック ***/
app.get('/api/check', async (c) => {
  const payload = c.get('jwtPayload');
  return c.json({ username: payload.sub });
});

/*
 * ---------------------
 * 好きな色アプリ用 API (ここが新しい部分)
 * ---------------------
 */

/* 連番ID生成 */
async function getNextId() {
  const key = ['counter', 'colors'];
  const res = await kv.atomic().sum(key, 1n).commit();
  const counter = await kv.get(key);
  return Number(counter.value);
}

/*** 回答の投稿 (POST) ***/
app.post('/api/colors', async (c) => {
  const payload = c.get('jwtPayload');
  const username = payload.sub;

  const body = await c.req.parseBody();
  const record = JSON.parse(body['record']); // { color: "#ff0000", comment: "..." }

  // 投稿者と日時を追加
  record['author'] = username;
  record['createdAt'] = new Date().toISOString();

  // ID生成
  const id = await getNextId();
  record['id'] = id;

  // 保存（キーは 'colors' と ID）
  await kv.set(['colors', id], record);

  c.status(201);
  return c.json({ record });
});

/*** 回答一覧の取得 (GET) ***/
app.get('/api/colors', async (c) => {
  // 'colors' のデータを全件取得
  const list = await kv.list({ prefix: ['colors'] });
  const records = await Array.fromAsync(list);

  // 新しい順（降順）にする
  const data = records.map((e) => e.value).reverse();

  return c.json(data);
});

/*** （デバッグ用）全ユーザー名の取得 ***/
app.get('/api/users', async (c) => {
  const list = await kv.list({ prefix: ['users'] });
  const users = [];
  for await (const entry of list) {
    users.push(entry.value.username);
  }
  return c.json(users);
});

/*
 * ---------------------
 * ウェブサーバー設定
 * ---------------------
 */

// ログイン済みなら入力画面(index.html)へ自動移動
app.on('GET', ['/signup.html', '/login.html'], async (c, next) => {
  const token = getCookie(c, COOKIE_NAME);
  if (token) return c.redirect('/index.html');
  await next();
});

app.get('/*', serveStatic({ root: './public' }));

Deno.serve(app.fetch);
