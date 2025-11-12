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
 * ユーザー認証
 */

/*** ユーザー登録 ***/
app.post('/api/signup', async (c) => {
  // 登録情報の取得
  const { username, password } = await c.req.json();
  if (!username || !password) {
    c.status(400); // 400 Bad Request
    return c.json({ message: 'ユーザー名とパスワードは必須です' });
  }

  // ユーザー名がすでにないか確認
  const userExists = await kv.get(['users', username]);
  if (userExists.value) {
    c.status(409); // 409 Conflict
    return c.json({ message: 'このユーザー名は既に使用されています' });
  }

  // パスワードをハッシュ化してユーザー名とともにデータベースに記録
  const hashedPassword = await hash(password);
  const user = { username, hashedPassword };
  await kv.set(['users', username], user);

  c.status(201); // 201 Created
  return c.json({ message: 'ユーザー登録が成功しました' });
});

/*** ログイン ***/
app.post('/api/login', async (c) => {
  // ログイン情報の取得
  const { username, password } = await c.req.json();
  const userEntry = await kv.get(['users', username]);
  const user = userEntry.value;

  if (!user) {
    c.status(401); // 401 Unauthorized
    return c.json({ message: 'ユーザー名が無効です' });
  }

  // ハッシュ化されたパスワードと比較
  if (!(await verify(password, user.hashedPassword))) {
    c.status(401); // 401 Unauthorized
    return c.json({ message: 'パスワードが無効です' });
  }

  // JWTの本体（ペイロード）を設定
  const payload = {
    sub: user.username, // ユーザー識別子（連番IDでもよい）
    // name: user.username,  // 表示用のユーザー名
    iat: Math.floor(Date.now() / 1000), // 発行日時
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 // 24時間有効
  };

  // JWT（トークン）を生成
  const token = await sign(payload, JWT_SECRET);

  // JWTをHttpOnlyのクッキーに設定
  setCookie(c, COOKIE_NAME, token, {
    path: '/',
    httpOnly: true,
    secure: false, // 開発環境のためfalseにしているが本番環境ではtrueにする
    sameSite: 'Strict',
    maxAge: 60 * 60 * 24 // 24時間有効
  });

  // レスポンス
  return c.json({ message: 'ログイン成功', username: user.username });
});

/* 上記以外の /api 以下へのアクセスにはログインが必要 */
app.use('/api/*', jwt({ secret: JWT_SECRET, cookie: COOKIE_NAME }));
// ↑ここで照合に成功すると jwtPayload というキーにJWTのペイロード（本体）が記録される
// ↑ログインしていなければ「401 Unauthorized」が返される

/*** ログアウト ***/
app.post('/api/logout', (c) => {
  // JWTを含むクッキーを削除
  deleteCookie(c, COOKIE_NAME, {
    path: '/',
    httpOnly: true,
    secure: false, // ログイン時の設定に合わせる
    sameSite: 'Strict'
  });

  c.status(204); // 204 No Content
  return c.body(null);
});

/*** ログインチェック ***/
app.get('/api/check', async (c) => {
  const payload = c.get('jwtPayload');
  const username = payload.sub;
  return c.json({ username });
});

/*
 * API
 */

/* 連番のIDを生成する関数 */
async function getNextId() {
  const key = ['counter', 'pokemons'];
  const res = await kv.atomic().sum(key, 1n).commit();
  if (!res.ok) {
    console.error('IDの生成に失敗しました。');
    return null;
  }
  const counter = await kv.get(key);

  return Number(counter.value);
}

/*** リソースの作成 ***/
app.post('/api/pokemons', async (c) => {
  // JWTからユーザー名を取得
  const payload = c.get('jwtPayload');
  const username = payload.sub;

  // 作成するポケモンデータの取得
  const body = await c.req.parseBody();
  const record = JSON.parse(body['record']);

  // IDと生成時刻を生成してレコードに追加
  const pokemonId = await getNextId();
  record['id'] = pokemonId;
  record['createdAt'] = new Date().toISOString();

  // リソースの作成
  await kv.set(['pokemons', username, pokemonId], record);

  // レスポンスの作成
  c.status(201); // 201 Created
  c.header('Location', `/pokemons/${pokemonId}`);

  return c.json({ record });
});

/*** コレクションの取得 ***/
app.get('/api/pokemons', async (c) => {
  const payload = c.get('jwtPayload');
  const username = payload.sub;

  // ユーザー名もprefixに入れて、ログインユーザーのデータのみを取得する
  const pkmns = await kv.list({ prefix: ['pokemons', username] });

  // リソースがあったとき
  const pkmnList = await Array.fromAsync(pkmns);
  if (pkmnList.length > 0) {
    return c.json(pkmnList.map((e) => e.value));
  }
  // リソースがなかったとき
  else {
    c.status(404); // 404 Not Found
    return c.json({ message: 'pokemonコレクションのデータは1つもありませんでした。' });
  }
});

/* レコードリストの削除（授業用） */
app.delete('/api/pokemons', async (c) => {
  const payload = c.get('jwtPayload');
  const username = payload.sub;

  const deleteList = await kv.list({ prefix: ['pokemons', username] });

  // レコードを一括で削除する
  const atomic = kv.atomic();
  for await (const entry of deleteList) atomic.delete(entry.key);
  const result = await atomic.commit();

  // レスポンス
  if (result.ok) {
    await kv.delete(['counter', 'pokemons']); // 連番IDをリセット
    c.status(); // 204 No Content
    return c.body(null);
  } else {
    c.status(503); // 503 Service Unavailable
    return c.json({ message: 'リソースの一括削除に失敗しました。' });
  }
});

// ユーザーアカウントの一括削除（勉強用）
app.delete('/api', async (c) => {
  const deleteList = await kv.list({ prefix: ['users'] });
  const atomic = kv.atomic();
  for await (const e of deleteList) atomic.delete(e.key);
  await atomic.commit();
  return c.body(null);
});

/*
 * ウェブサーバー
 */

// ログイン済みならリダイレクト
app.on('GET', ['/signup.html', '/login.html'], async (c, next) => {
  const token = getCookie(c, COOKIE_NAME);
  if (token) {
    return c.redirect('/index.html'); // アプリページへリダイレクト
  }
  await next();
});

// ウェブコンテンツ（静的ファイル）の置き場を指定
app.get('/*', serveStatic({ root: './public' }));

Deno.serve(app.fetch);
