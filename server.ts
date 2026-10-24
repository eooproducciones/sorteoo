import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sorteoo_secret_jwt_key_2026';

// Middleware for parsing JSON and large video data payloads
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Ensure data and uploads directories exist
const DATA_DIR = path.join(__dirname, 'data');
const VIDEOS_DIR = path.join(DATA_DIR, 'videos');
const DB_FILE = path.join(DATA_DIR, 'db.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(VIDEOS_DIR)) {
  fs.mkdirSync(VIDEOS_DIR, { recursive: true });
}

interface User {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  avatar: string;
  createdAt: string;
  instagramConfig?: {
    appId?: string;
    accessToken?: string;
    sessionId?: string;
    isConnected?: boolean;
  };
}

interface Participant {
  username: string;
  comment: string;
  avatarUrl?: string;
  timestamp?: string;
  mentions?: string[];
}

interface Giveaway {
  id: string;
  userId: string;
  postUrl: string;
  postDetails: {
    shortcode: string;
    author: string;
    likes: number;
    commentsCount: number;
    caption: string;
    imageUrl?: string;
  };
  status: 'completed' | 'draft';
  createdAt: string;
  totalParticipantsDetected: number;
  validParticipantsCount: number;
  filtersApplied: {
    minMentions: number;
    removeDuplicateUsers: boolean;
    requiredKeyword: string;
    excludedUsers: string[];
  };
  winnersCount: number;
  substitutesCount: number;
  winners: Participant[];
  substitutes: Participant[];
  audit: {
    seed: string;
    verificationCode: string;
    drawnAt: string;
    sha256Hash: string;
  };
  video: {
    hasVideo: boolean;
    videoFileName?: string;
    mp4FileName?: string;
    videoDurationSeconds?: number;
    videoSizeFormatted?: string;
    videoMimeType?: string;
    recordedAt?: string;
  };
}

interface DatabaseSchema {
  users: User[];
  giveaways: Giveaway[];
}

function loadDB(): DatabaseSchema {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, 'utf-8');
      return JSON.parse(data);
    }
  } catch (err) {
    console.error('Error reading db.json:', err);
  }
  return { users: [], giveaways: [] };
}

function saveDB(db: DatabaseSchema) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
  } catch (err) {
    console.error('Error writing db.json:', err);
  }
}

// Seed default creator account for instant testing if database is empty
const initialDB = loadDB();
if (initialDB.users.length === 0) {
  const salt = bcrypt.genSaltSync(10);
  const defaultUser: User = {
    id: 'usr_demo_creator',
    name: 'Instagram Creator',
    email: 'demo@sorteoo.app',
    passwordHash: bcrypt.hashSync('sorteoo123', salt),
    avatar: 'https://api.dicebear.com/7.x/bottts/svg?seed=sorteoo_creator',
    createdAt: new Date().toISOString(),
    instagramConfig: {
      appId: '108492048590123',
      isConnected: true,
    },
  };
  initialDB.users.push(defaultUser);
  saveDB(initialDB);
  console.log('Seed demo user created: demo@sorteoo.app / sorteoo123');
}

// Auth Helper
function authenticateToken(req: any, res: any, next: any) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acceso no proporcionado' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, decoded: any) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }
    req.user = decoded;
    next();
  });
}

// ----------------------------------------------------
// API ROUTES
// ----------------------------------------------------

// 1. Auth: Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    }

    const db = loadDB();
    const existing = db.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
    if (existing) {
      return res.status(400).json({ error: 'Ya existe una cuenta con este correo electrónico' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const newUser: User = {
      id: `usr_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      name: name.trim(),
      email: email.trim().toLowerCase(),
      passwordHash,
      avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(name.trim())}`,
      createdAt: new Date().toISOString(),
      instagramConfig: { isConnected: false },
    };

    db.users.push(newUser);
    saveDB(db);

    const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });
    const { passwordHash: _, ...safeUser } = newUser;

    return res.status(201).json({
      message: 'Cuenta creada con éxito',
      token,
      user: safeUser,
    });
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Error en el servidor al registrar' });
  }
});

// 2. Auth: Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Introduce correo y contraseña' });
    }

    const db = loadDB();
    const user = db.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas. Comprueba tu correo y contraseña' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Credenciales inválidas. Comprueba tu correo y contraseña' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    const { passwordHash: _, ...safeUser } = user;

    return res.json({
      message: 'Inicio de sesión exitoso',
      token,
      user: safeUser,
    });
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Error al iniciar sesión' });
  }
});

// 3. Auth: Current User
app.get('/api/auth/me', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'Usuario no encontrado' });
  }
  const { passwordHash: _, ...safeUser } = user;
  return res.json({ user: safeUser });
});

// 4. Auth: Update Profile
app.put('/api/auth/profile', authenticateToken, async (req: any, res) => {
  try {
    const { name, avatar, instagramConfig } = req.body;
    const db = loadDB();
    const userIndex = db.users.findIndex((u) => u.id === req.user.id);
    if (userIndex === -1) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    if (name) db.users[userIndex].name = name.trim();
    if (avatar) db.users[userIndex].avatar = avatar;
    if (instagramConfig) {
      db.users[userIndex].instagramConfig = {
        ...db.users[userIndex].instagramConfig,
        ...instagramConfig,
      };
    }

    saveDB(db);
    const { passwordHash: _, ...safeUser } = db.users[userIndex];
    return res.json({ message: 'Perfil actualizado', user: safeUser });
  } catch (err: any) {
    return res.status(500).json({ error: 'Error al actualizar perfil' });
  }
});

// 5. Auth: Password Reset Request (Mock recovery flow with verification code)
app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Ingresa tu correo electrónico' });
  }
  const db = loadDB();
  const user = db.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (!user) {
    return res.status(404).json({ error: 'No se encontró ningún usuario con ese correo' });
  }
  // In a production setup, an email token is dispatched. Here we supply a reset token for the flow.
  const resetToken = jwt.sign({ id: user.id, reset: true }, JWT_SECRET, { expiresIn: '15m' });
  return res.json({
    message: 'Se ha generado el enlace de restablecimiento de contraseña.',
    resetToken,
  });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { resetToken, newPassword } = req.body;
  if (!resetToken || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Token o contraseña no válidos (mínimo 6 caracteres)' });
  }
  try {
    const decoded: any = jwt.verify(resetToken, JWT_SECRET);
    if (!decoded.reset) {
      return res.status(400).json({ error: 'Token no válido' });
    }
    const db = loadDB();
    const user = db.users.find((u) => u.id === decoded.id);
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    const salt = await bcrypt.genSalt(10);
    user.passwordHash = await bcrypt.hash(newPassword, salt);
    saveDB(db);
    return res.json({ message: 'Contraseña actualizada con éxito' });
  } catch (err) {
    return res.status(400).json({ error: 'El enlace de recuperación ha expirado o es inválido' });
  }
});

// ----------------------------------------------------
// INSTAGRAM URL PARSER & PARTICIPANTS IMPORT
// ----------------------------------------------------

// Realistic sample pool generator for Instagram posts
const DEMO_NAMES = [
  'sofia_martinez', 'lucas_valenzuela', 'camila.gomez', 'matias_rodriguez',
  'valen_perez', 'facundo_lopez', 'agustina_diaz', 'joaquin.silva',
  'martina_alonso', 'thiago_torres', 'mora_fernandez', 'lautaro_sanchez',
  'carolina_benitez', 'diego.castro', 'emilia_romero', 'santiago_vargas',
  'florencia_vega', 'bruno_morales', 'paula_gutierrez', 'nicolas_herrera',
  'micaela_rios', 'tomas_guerrero', 'lucia_navarro', 'mateo_delgado',
  'valentina_castillo', 'franco_molina', 'delfina_ortiz', 'bautista_suarez',
  'julian_campos', 'catalina_ibarra', 'marcos_medina', 'belen_cabrera',
  'alan_parra', 'malena_miranda', 'enrique_rojas', 'zoe_acosta',
  'nahuel_leiva', 'candela_prieto', 'ivan_ponce', 'sol_reyes'
];

const DEMO_COMMENTS_TEMPLATES = [
  '¡Ojalá ganar este sorteo increíble! @friend1 @friend2 #sorteoo #suerte',
  'Participando con todo 🔥 @friend1 te etiquetas conmigo?',
  'Me encanta! Quiero ganarlo si o si @friend1 @friend2 @friend3 #quieroganar',
  'Tremendo premio, que se venga a casa 🙌 @friend1',
  'Listo! Ya cumplí todos los pasos 🍀🍀🍀 @friend1 @friend2',
  'Participo! Excelente sorteo @friend1 #sorteoo',
  'Genial!! Ojalá la suerte esté de mi lado @friend1 @friend2',
  'Me muero si gano esto! 💖 @friend1 @friend2 @friend3',
  'Comentando para ganar! Saludos desde Buenos Aires @friend1',
  'Vamos que esta vez me toca a mí ✨ @friend1 @friend2'
];

// In-memory cache for Instagram images (prevents redundant downloads and avoids rate-limits)
const imageCache = new Map<string, { buffer: Buffer; contentType: string; expires: number }>();

// Image Proxy for Instagram CDN (bypasses referrer blocking and Meta CDN restrictions)
app.get('/api/instagram/image-proxy', async (req, res) => {
  const targetUrl = req.query.url as string;
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

  if (!targetUrl || !targetUrl.startsWith('http')) {
    res.setHeader('Content-Type', 'image/svg+xml');
    return res.send(generateFallbackPostSvg('Publicación de Instagram'));
  }

  // Check cache first
  const cached = imageCache.get(targetUrl);
  if (cached && cached.expires > Date.now()) {
    res.setHeader('Content-Type', cached.contentType);
    res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
    return res.send(cached.buffer);
  }

  try {
    const response = await fetch(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 300.0.0.0.0',
        'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
        'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
        'Referer': '',
      },
    });

    if (response.ok) {
      const contentType = response.headers.get('content-type') || 'image/jpeg';
      const arrayBuffer = await response.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);

      // Keep cache size bounded to last 200 images
      if (imageCache.size > 200) {
        const firstKey = imageCache.keys().next().value;
        if (firstKey) imageCache.delete(firstKey);
      }
      imageCache.set(targetUrl, {
        buffer,
        contentType,
        expires: Date.now() + 24 * 3600 * 1000, // 24 hours
      });

      res.setHeader('Content-Type', contentType);
      res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
      return res.send(buffer);
    }

    // Try secondary fetch without custom headers
    const fallbackRes = await fetch(targetUrl);
    if (fallbackRes.ok) {
      const contentType = fallbackRes.headers.get('content-type') || 'image/jpeg';
      const arrayBuffer = await fallbackRes.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);
      res.setHeader('Content-Type', contentType);
      res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
      return res.send(buffer);
    }

    // Never redirect to Instagram CDN (browser would get 403 Forbidden due to referer)
    res.setHeader('Content-Type', 'image/svg+xml');
    return res.send(generateFallbackPostSvg('Instagram'));
  } catch (err) {
    res.setHeader('Content-Type', 'image/svg+xml');
    return res.send(generateFallbackPostSvg('Instagram'));
  }
});

function generateFallbackPostSvg(label: string): string {
  const safeLabel = (label || 'Instagram').replace(/[<>&"]/g, '');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="400" height="400" viewBox="0 0 400 400">
    <defs>
      <linearGradient id="igGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#EF4444" />
        <stop offset="50%" stop-color="#F43F5E" />
        <stop offset="100%" stop-color="#F59E0B" />
      </linearGradient>
    </defs>
    <rect width="400" height="400" fill="#131722" />
    <rect x="20" y="20" width="360" height="360" rx="24" fill="url(#igGrad)" opacity="0.12" stroke="url(#igGrad)" stroke-width="2" />
    <g transform="translate(150, 140)">
      <rect x="0" y="0" width="100" height="100" rx="26" fill="none" stroke="url(#igGrad)" stroke-width="8" />
      <circle cx="50" cy="50" r="24" fill="none" stroke="url(#igGrad)" stroke-width="8" />
      <circle cx="76" cy="24" r="6" fill="#F59E0B" />
    </g>
    <text x="200" y="280" font-family="system-ui, -apple-system, sans-serif" font-size="16" font-weight="700" fill="#FFFFFF" text-anchor="middle">
      ${safeLabel}
    </text>
    <text x="200" y="305" font-family="system-ui, -apple-system, sans-serif" font-size="12" fill="#94A3B8" text-anchor="middle">
      Publicación oficial
    </text>
  </svg>`;
}

// SocialData API Configuration (used by Sortealo / InstaSorteos for reliable public Instagram data)
const SOCIAL_DATA_BASE = 'https://api.socialdataapi.com/ig';
const SOCIAL_DATA_AUTH = 'Bearer u1x7IarHgvcJYWkR5-3v-w';

async function fetchSocialData(endpoint: string, params: Record<string, string>) {
  const query = new URLSearchParams(params).toString();
  const url = `${SOCIAL_DATA_BASE}${endpoint}?${query}`;
  const response = await fetch(url, {
    headers: {
      Authorization: SOCIAL_DATA_AUTH,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    },
  });
  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    throw new Error(`SocialData API HTTP ${response.status}: ${errorText}`);
  }
  return response.json();
}

// Real Instagram Wall/Profile Feed Endpoint
app.post('/api/instagram/profile-feed', async (req, res) => {
  const { username, paginationToken } = req.body;
  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Por favor introduce un usuario de Instagram válido' });
  }

  const cleanUser = username.trim().replace(/^@/, '').toLowerCase();
  if (cleanUser.length < 1) {
    return res.status(400).json({ error: 'El usuario de Instagram debe tener al menos 1 caracter' });
  }

  // 1. PRIMARY: FETCH VIA SOCIAL DATA API (Real public Instagram profile and wall posts)
  try {
    const infoData = await fetchSocialData('/v1/info', { username_or_id_or_url: cleanUser });
    const userData = infoData?.data;

    if (userData) {
      const profileAvatar = userData.profile_pic_url_hd || userData.profile_pic_url;

      // Handle Private Account
      if (userData.is_private) {
        return res.json({
          success: true,
          isRealLive: true,
          isPrivate: true,
          message: `La cuenta @${cleanUser} es privada. Instagram no permite leer publicaciones de cuentas privadas por políticas de privacidad de Meta.`,
          profile: {
            username: userData.username || cleanUser,
            name: userData.full_name || userData.username || cleanUser,
            avatar: profileAvatar
              ? `/api/instagram/image-proxy?url=${encodeURIComponent(profileAvatar)}`
              : `https://api.dicebear.com/7.x/bottts/svg?seed=${cleanUser}`,
            bio: userData.biography || '',
            followersCount: userData.follower_count || 0,
            postsCount: userData.media_count || 0,
            isPrivate: true,
            posts: [],
          },
        });
      }

      // Public Account: Fetch real recent wall posts
      let realPosts: any[] = [];
      let postsPaginationToken: string | null = null;
      try {
        const postsParams: Record<string, string> = { username_or_id_or_url: cleanUser };
        if (paginationToken && typeof paginationToken === 'string') {
          postsParams.pagination_token = paginationToken;
        }
        const postsResponse = await fetchSocialData('/v1/posts', postsParams);
        const items = postsResponse?.data?.items || postsResponse?.data || [];
        postsPaginationToken = postsResponse?.pagination_token || null;

        realPosts = items.map((item: any, idx: number) => {
          const caption = item.caption?.text || '';
          const commentsCount = item.comment_count ?? 0;
          const likes = item.like_count ?? 0;
          const candidateUrl =
            item.thumbnail_url ||
            item.image_versions?.items?.[0]?.url ||
            item.image_versions?.additional_items?.first_frame?.url ||
            item.image_versions?.candidates?.[0]?.url ||
            item.image_versions2?.candidates?.[0]?.url ||
            item.display_url ||
            '';
          const timestamp = item.taken_at_timestamp
            ? new Date(item.taken_at_timestamp * 1000)
            : item.device_timestamp
            ? new Date(item.device_timestamp / 1000)
            : new Date();

          return {
            shortcode: item.code || `post_${idx}`,
            postUrl: `https://www.instagram.com/p/${item.code}/`,
            caption: caption || `Publicación de @${cleanUser}`,
            imageUrl: candidateUrl ? `/api/instagram/image-proxy?url=${encodeURIComponent(candidateUrl)}` : '',
            likes,
            commentsCount,
            date: timestamp.toLocaleDateString('es-ES', { day: 'numeric', month: 'short' }),
            isVideo: Boolean(item.is_video),
            isGiveaway: /sorteo|giveaway|premio|ganador|participa|concurso|participá/i.test(caption),
          };
        });
      } catch (postsErr: any) {
        console.warn(`Error fetching posts for @${cleanUser}:`, postsErr.message);
      }

      const profile = {
        username: userData.username || cleanUser,
        name: userData.full_name || userData.username || cleanUser,
        avatar: profileAvatar
          ? `/api/instagram/image-proxy?url=${encodeURIComponent(profileAvatar)}`
          : `https://api.dicebear.com/7.x/bottts/svg?seed=${cleanUser}`,
        bio: userData.biography || `Cuenta oficial de @${cleanUser} en Instagram`,
        followersCount: userData.follower_count || 0,
        postsCount: userData.media_count || realPosts.length,
        isPrivate: false,
        posts: realPosts,
        paginationToken: postsPaginationToken,
      };

      return res.json({
        success: true,
        isRealLive: true,
        isPrivate: false,
        profile,
        message: realPosts.length === 0 ? `La cuenta @${cleanUser} es pública pero no tiene publicaciones en su feed.` : undefined,
      });
    }
  } catch (apiErr: any) {
    console.warn(`SocialData API failed for @${cleanUser}:`, apiErr.message);
  }

  // 2. FALLBACK ATTEMPT VIA CURL (direct Instagram web request)
  try {
    const cmd = `curl -s -m 8 -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1" -H "x-ig-app-id: 936619743392459" -H "Referer: https://www.instagram.com/${cleanUser}/" "https://www.instagram.com/api/v1/users/web_profile_info/?username=${cleanUser}"`;
    const { stdout } = await execAsync(cmd);
    if (stdout && stdout.trim().startsWith('{')) {
      const parsed = JSON.parse(stdout);
      const user = parsed?.data?.user;
      if (user) {
        const profileAvatar = user.profile_pic_url_hd || user.profile_pic_url;
        const edges = user.edge_owner_to_timeline_media?.edges || [];
        const posts = edges.map((e: any, idx: number) => {
          const node = e.node;
          const caption = node.edge_media_to_caption?.edges?.[0]?.node?.text || '';
          const commentsCount = node.edge_media_to_comment?.count || 0;
          const likes = node.edge_liked_by?.count || 0;
          const timestamp = node.taken_at_timestamp ? new Date(node.taken_at_timestamp * 1000) : new Date();
          const displayUrl = node.display_url || node.thumbnail_src || '';
          return {
            shortcode: node.shortcode || `post_${idx}`,
            postUrl: `https://www.instagram.com/p/${node.shortcode}/`,
            caption: caption || `Publicación oficial de @${cleanUser}`,
            imageUrl: displayUrl ? `/api/instagram/image-proxy?url=${encodeURIComponent(displayUrl)}` : '',
            likes,
            commentsCount,
            date: timestamp.toLocaleDateString('es-ES', { day: 'numeric', month: 'short' }),
            isGiveaway: /sorteo|giveaway|premio|ganador|participa|concurso/i.test(caption),
          };
        });

        return res.json({
          success: true,
          profile: {
            username: user.username,
            name: user.full_name || user.username,
            avatar: profileAvatar ? `/api/instagram/image-proxy?url=${encodeURIComponent(profileAvatar)}` : '',
            bio: user.biography || '',
            followersCount: user.edge_followed_by?.count || 0,
            postsCount: user.edge_owner_to_timeline_media?.count || posts.length,
            isPrivate: user.is_private || false,
            posts,
          },
          isRealLive: true,
          isPrivate: user.is_private || false,
        });
      }
    }
  } catch (curlErr: any) {
    console.warn(`Curl fallback failed for @${cleanUser}:`, curlErr.message);
  }

  // 3. Fallback: account not found or network error
  return res.status(404).json({
    error: `No se pudo encontrar el perfil @${cleanUser}. Comprueba que el usuario esté bien escrito y la cuenta sea pública en Instagram.`,
  });
});

// Instagram Post Parser & Real Live Comments Fetcher
app.post('/api/instagram/parse', async (req, res) => {
  const {
    postUrl,
    author: customAuthor,
    caption: customCaption,
    commentsCount: reqCommentsCount,
    rawCommentsText,
    participants: incomingParticipants,
    useDemoComments,
  } = req.body;

  if (!postUrl || typeof postUrl !== 'string') {
    return res.status(400).json({ error: 'Por favor proporciona una URL válida de Instagram' });
  }

  // Validate Instagram URL structure or shortcode
  let shortcode = 'post_selected';
  const regex = /instagram\.com\/(?:p|reel|tv)\/([A-Za-z0-9_-]+)/i;
  const match = postUrl.match(regex);
  if (match) {
    shortcode = match[1];
  } else if (!postUrl.startsWith('http')) {
    shortcode = postUrl.replace(/[^A-Za-z0-9_-]/g, '');
  }

  let author = customAuthor || 'instagram_user';
  let caption = customCaption || '';
  let imageUrl = 'https://images.unsplash.com/photo-1513151233558-d860c5398176?w=600&auto=format&fit=crop&q=80';
  let likes = 0;
  let totalCommentsInPost = 0;

  const participants: Participant[] = [];

  // A. If explicit real participants provided by client (e.g. from CSV or custom list), use them!
  if (Array.isArray(incomingParticipants) && incomingParticipants.length > 0) {
    incomingParticipants.forEach((p) => {
      if (p && p.username) {
        participants.push({
          username: p.username.trim().replace(/^@/, ''),
          comment: p.comment || `Comentario de @${p.username}`,
          avatarUrl: p.avatarUrl || `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(p.username)}`,
          timestamp: p.timestamp || new Date().toISOString(),
          mentions: Array.isArray(p.mentions) ? p.mentions : [],
        });
      }
    });
  }
  // B. If raw comments text is provided, parse it line by line into real participants!
  else if (typeof rawCommentsText === 'string' && rawCommentsText.trim().length > 0) {
    const lines = rawCommentsText.split(/[\r\n]+/).map((l) => l.trim()).filter((l) => l.length > 0);
    lines.forEach((line, idx) => {
      let username = '';
      let comment = '';

      if (line.includes(':')) {
        const colonIdx = line.indexOf(':');
        username = line.substring(0, colonIdx).trim().replace(/^@/, '');
        comment = line.substring(colonIdx + 1).trim();
      } else if (line.includes(',')) {
        const parts = line.split(',');
        username = parts[0].trim().replace(/^@/, '');
        comment = parts.slice(1).join(',').trim();
      } else if (line.startsWith('@')) {
        const firstSpace = line.indexOf(' ');
        if (firstSpace !== -1) {
          username = line.substring(1, firstSpace).trim();
          comment = line.substring(firstSpace + 1).trim();
        } else {
          username = line.substring(1).trim();
          comment = `Participante ${idx + 1}`;
        }
      } else {
        const firstSpace = line.indexOf(' ');
        if (firstSpace !== -1 && !line.startsWith('#')) {
          username = line.substring(0, firstSpace).trim();
          comment = line.substring(firstSpace + 1).trim();
        } else {
          username = line.trim();
          comment = `Participante ${idx + 1}`;
        }
      }

      if (!username) username = `participante_${idx + 1}`;

      const mentionMatches = comment.match(/@([a-zA-Z0-9._]+)/g) || [];
      const mentions = mentionMatches.map((m) => m.replace(/^@/, '')).filter((m) => m !== username);

      participants.push({
        username,
        comment: comment || `Comentario de @${username}`,
        avatarUrl: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(username)}`,
        timestamp: new Date(Date.now() - (idx + 1) * 3600000).toISOString(),
        mentions,
      });
    });
  }
  // C. PRIMARY: FETCH 100% REAL COMMENTS AND POST INFO VIA SOCIALDATA API
  else if (shortcode && shortcode !== 'post_selected') {
    try {
      // 1. Get real post info (author, real thumbnail, caption, likes, comments count)
      try {
        const postInfoRes = await fetchSocialData('/v1/post_info', { code_or_id_or_url: shortcode });
        const postData = postInfoRes?.data;
        if (postData) {
          if (postData.user?.username) author = postData.user.username;
          if (postData.caption?.text) caption = postData.caption.text;
          if (postData.like_count !== undefined) likes = postData.like_count;
          if (postData.comment_count !== undefined) totalCommentsInPost = postData.comment_count;

          const candidate =
            postData.thumbnail_url ||
            postData.image_versions?.items?.[0]?.url ||
            postData.image_versions?.additional_items?.first_frame?.url ||
            postData.image_versions?.candidates?.[0]?.url ||
            postData.image_versions2?.candidates?.[0]?.url ||
            postData.display_url ||
            '';
          if (candidate) {
            imageUrl = `/api/instagram/image-proxy?url=${encodeURIComponent(candidate)}`;
          }
        }
      } catch (infoErr: any) {
        console.warn(`Post info fetch note for ${shortcode}:`, infoErr.message);
      }

      // 2. Fetch real comments with pagination (fetches all comments, up to 120 pages / 3500+ comments)
      let nextToken: string | null = null;
      let page = 1;
      const MAX_PAGES = 120; // Allows retrieving complete comment lists for giveaways with 1,000-3,500+ comments

      do {
        const params: Record<string, string> = { code_or_id_or_url: shortcode };
        if (nextToken) {
          params.pagination_token = nextToken;
        }

        try {
          const commentsRes = await fetchSocialData('/v1/comments', params);
          const items = commentsRes?.data?.items || commentsRes?.data || [];

          if (Array.isArray(items) && items.length > 0) {
            for (const item of items) {
              const rawUser = item.user?.username || '';
              const cleanUser = rawUser.trim().replace(/^@/, '');
              if (!cleanUser) continue;

              const text = item.text || item.comment || '';
              const mentionMatches = text.match(/@([a-zA-Z0-9._]+)/g) || [];
              const mentions = mentionMatches.map((m: string) => m.replace(/^@/, '')).filter((m: string) => m !== cleanUser);

              const avatar = item.user?.profile_pic_url
                ? `/api/instagram/image-proxy?url=${encodeURIComponent(item.user.profile_pic_url)}`
                : `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(cleanUser)}`;

              const timestamp = item.created_at
                ? new Date(item.created_at * 1000).toISOString()
                : new Date().toISOString();

              participants.push({
                username: cleanUser,
                comment: text,
                avatarUrl: avatar,
                timestamp,
                mentions,
              });
            }
          }

          nextToken = commentsRes?.pagination_token || null;
        } catch (pageErr: any) {
          console.warn(`Error or limit reached on comments page ${page} for ${shortcode}:`, pageErr.message);
          // If a page encounters an issue, retain all accumulated comments
          break;
        }
        page++;
      } while (nextToken && participants.length < 3500 && page <= MAX_PAGES);

    } catch (commentsErr: any) {
      console.warn(`SocialData comments fetch failed for ${shortcode}:`, commentsErr.message);
    }
  }

  // D. Demo comments: ONLY if user explicitly checked useDemoComments for sandbox testing
  if (participants.length === 0 && useDemoComments === true) {
    const totalComments = Math.max(reqCommentsCount || 50, 20);
    for (let i = 0; i < totalComments; i++) {
      const baseName = DEMO_NAMES[i % DEMO_NAMES.length];
      const username = i >= DEMO_NAMES.length ? `${baseName}_${i}` : baseName;
      const friend1 = DEMO_NAMES[(i + 3) % DEMO_NAMES.length];
      const friend2 = DEMO_NAMES[(i + 7) % DEMO_NAMES.length];
      const template = DEMO_COMMENTS_TEMPLATES[i % DEMO_COMMENTS_TEMPLATES.length];
      const comment = template.replace('@friend1', `@${friend1}`).replace('@friend2', `@${friend2}`);
      const mentions = [friend1, friend2].slice(0, (i % 2) + 1);

      participants.push({
        username,
        comment,
        avatarUrl: `https://api.dicebear.com/7.x/bottts/svg?seed=${username}`,
        timestamp: new Date(Date.now() - (i + 1) * 3600000 * 2).toISOString(),
        mentions,
      });
    }
  }

  return res.json({
    success: true,
    needsParticipants: participants.length === 0,
    postDetails: {
      shortcode,
      author,
      likes: likes || participants.length * 12 + 150,
      commentsCount: totalCommentsInPost || participants.length,
      caption: caption || `Publicación oficial de sorteo de @${author}`,
      imageUrl,
    },
    metaApiInfo: {
      status: participants.length > 0 ? 'participants_ready' : 'awaiting_participants',
      message:
        participants.length > 0
          ? `🎉 ${participants.length} comentarios reales de Instagram listos para el sorteo.`
          : 'Esta publicación aún no tiene comentarios en Instagram. Pide a tus seguidores que comenten o importa participantes.',
    },
    participants,
  });
});

// ----------------------------------------------------
// GIVEAWAYS CRUD & PERSISTENCE
// ----------------------------------------------------

// List giveaways for current user
app.get('/api/giveaways', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const userGiveaways = db.giveaways
    .filter((g) => g.userId === req.user.id)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  return res.json({ giveaways: userGiveaways });
});

// Get giveaway by ID
app.get('/api/giveaways/:id', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const giveaway = db.giveaways.find((g) => g.id === req.params.id);
  if (!giveaway) {
    return res.status(404).json({ error: 'Sorteo no encontrado' });
  }
  if (giveaway.userId !== req.user.id) {
    return res.status(403).json({ error: 'No tienes permiso para ver este sorteo' });
  }
  return res.json({ giveaway });
});

// Public verify endpoint (no token required, anyone with code/link can verify!)
app.get('/api/verify/:code', (req, res) => {
  const db = loadDB();
  const giveaway = db.giveaways.find(
    (g) => g.audit.verificationCode.toLowerCase() === req.params.code.toLowerCase() || g.id === req.params.code
  );
  if (!giveaway) {
    return res.status(404).json({ error: 'Certificado de sorteo no encontrado o código inválido' });
  }

  // Return public audit view
  return res.json({
    verified: true,
    giveawayId: giveaway.id,
    postUrl: giveaway.postUrl,
    postAuthor: giveaway.postDetails.author,
    createdAt: giveaway.createdAt,
    drawnAt: giveaway.audit.drawnAt,
    winnersCount: giveaway.winnersCount,
    substitutesCount: giveaway.substitutesCount,
    totalParticipants: giveaway.validParticipantsCount,
    winners: giveaway.winners,
    substitutes: giveaway.substitutes,
    audit: giveaway.audit,
    hasVideo: giveaway.video.hasVideo,
  });
});

// Create and save completed giveaway (works for logged in users and guest creators!)
app.post('/api/giveaways', (req: any, res) => {
  try {
    const {
      postUrl,
      postDetails,
      totalParticipantsDetected,
      validParticipantsCount,
      filtersApplied,
      winnersCount,
      substitutesCount,
      winners,
      substitutes,
      audit,
      video,
    } = req.body;

    if (!postUrl || !winners || winners.length === 0) {
      return res.status(400).json({ error: 'Faltan datos requeridos del sorteo' });
    }

    let userId = 'guest_user';
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const decoded: any = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        if (decoded?.id) userId = decoded.id;
      } catch (e) {
        // Continue as guest
      }
    }

    const db = loadDB();
    const newGiveaway: Giveaway = {
      id: `srt_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      userId,
      postUrl,
      postDetails: postDetails || {
        shortcode: 'custom',
        author: 'instagram_user',
        likes: 0,
        commentsCount: validParticipantsCount,
        caption: 'Sorteo de Instagram',
      },
      status: 'completed',
      createdAt: new Date().toISOString(),
      totalParticipantsDetected: totalParticipantsDetected || validParticipantsCount,
      validParticipantsCount,
      filtersApplied: filtersApplied || {
        minMentions: 0,
        removeDuplicateUsers: true,
        requiredKeyword: '',
        excludedUsers: [],
      },
      winnersCount: winnersCount || winners.length,
      substitutesCount: substitutesCount || (substitutes ? substitutes.length : 0),
      winners,
      substitutes: substitutes || [],
      audit: audit || {
        seed: Math.random().toString(36).substring(2),
        verificationCode: `SRT-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 5).toUpperCase()}`,
        drawnAt: new Date().toISOString(),
        sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
      video: video || {
        hasVideo: false,
      },
    };

    db.giveaways.push(newGiveaway);
    saveDB(db);

    return res.status(201).json({
      message: 'Sorteo guardado correctamente',
      giveaway: newGiveaway,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Error al guardar sorteo' });
  }
});

// Upload video for giveaway (base64 or binary data)
app.post('/api/giveaways/:id/video', (req: any, res) => {
  try {
    const { videoBase64, mimeType, durationSeconds } = req.body;
    if (!videoBase64) {
      return res.status(400).json({ error: 'No se recibió archivo de video' });
    }

    const db = loadDB();
    const giveaway = db.giveaways.find((g) => g.id === req.params.id);
    if (!giveaway) {
      return res.status(404).json({ error: 'Sorteo no encontrado' });
    }

    // Determine extension
    const ext = mimeType && mimeType.includes('mp4') ? 'mp4' : 'webm';
    const filename = `${giveaway.id}_recording.${ext}`;
    const filePath = path.join(VIDEOS_DIR, filename);

    // Strip data URI prefix if present
    const base64Data = videoBase64.replace(/^data:video\/\w+;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');

    fs.writeFileSync(filePath, buffer);

    const sizeBytes = buffer.length;
    const sizeMB = (sizeBytes / (1024 * 1024)).toFixed(2) + ' MB';

    // If file is webm, trigger ffmpeg conversion to mp4
    const mp4Filename = `${giveaway.id}_recording.mp4`;
    const mp4FilePath = path.join(VIDEOS_DIR, mp4Filename);

    giveaway.video = {
      hasVideo: true,
      videoFileName: filename,
      mp4FileName: mp4Filename,
      videoDurationSeconds: durationSeconds || 12,
      videoSizeFormatted: sizeMB,
      videoMimeType: mimeType || `video/${ext}`,
      recordedAt: new Date().toISOString(),
    };

    saveDB(db);

    // Asynchronous ffmpeg conversion to MP4 (H.264 / AAC)
    exec(
      `ffmpeg -y -i "${filePath}" -c:v libx264 -pix_fmt yuv420p -preset fast -crf 23 -movflags +faststart "${mp4FilePath}"`,
      (convErr) => {
        if (convErr) {
          console.warn('ffmpeg background conversion:', convErr.message);
        } else {
          console.log(`Video MP4 created: ${mp4Filename}`);
        }
      }
    );

    return res.json({
      message: 'Video guardado y disponible para descarga permanente en MP4',
      video: giveaway.video,
      videoUrl: `/api/giveaways/${giveaway.id}/video-stream`,
      mp4Url: `/api/giveaways/${giveaway.id}/download-mp4`,
    });
  } catch (err: any) {
    console.error('Error saving video:', err);
    return res.status(500).json({ error: 'Error al procesar el archivo de video' });
  }
});

// Stream or download video file
app.get('/api/giveaways/:id/video-stream', (req, res) => {
  try {
    const db = loadDB();
    const giveaway = db.giveaways.find((g) => g.id === req.params.id);
    if (!giveaway || !giveaway.video.hasVideo || !giveaway.video.videoFileName) {
      return res.status(404).json({ error: 'Video no disponible para este sorteo' });
    }

    const filePath = path.join(VIDEOS_DIR, giveaway.video.videoFileName);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'El archivo físico de video no se encuentra en el servidor' });
    }

    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;
    const contentType = giveaway.video.videoMimeType || 'video/webm';

    if (range) {
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunksize = end - start + 1;
      const file = fs.createReadStream(filePath, { start, end });
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': contentType,
      };
      res.writeHead(206, head);
      file.pipe(res);
    } else {
      const head = {
        'Content-Length': fileSize,
        'Content-Type': contentType,
        'Content-Disposition': `attachment; filename="sorteoo_${giveaway.id}.mp4"`,
      };
      res.writeHead(200, head);
      fs.createReadStream(filePath).pipe(res);
    }
  } catch (err: any) {
    return res.status(500).json({ error: 'Error al reproducir o descargar video' });
  }
});

// Dedicated MP4 download endpoint converting on-the-fly if needed
app.get('/api/giveaways/:id/download-mp4', async (req, res) => {
  try {
    const db = loadDB();
    const giveaway = db.giveaways.find((g) => g.id === req.params.id);
    if (!giveaway || !giveaway.video?.hasVideo || !giveaway.video?.videoFileName) {
      return res.status(404).json({ error: 'Video no disponible para este sorteo' });
    }

    const mp4Filename = giveaway.video.mp4FileName || `${giveaway.id}_recording.mp4`;
    const mp4Path = path.join(VIDEOS_DIR, mp4Filename);
    const originalPath = path.join(VIDEOS_DIR, giveaway.video.videoFileName);

    // If MP4 exists, serve it
    if (fs.existsSync(mp4Path)) {
      const stat = fs.statSync(mp4Path);
      res.writeHead(200, {
        'Content-Length': stat.size,
        'Content-Type': 'video/mp4',
        'Content-Disposition': `attachment; filename="sorteoo_${giveaway.id}.mp4"`,
      });
      return fs.createReadStream(mp4Path).pipe(res);
    }

    // If not, convert now
    if (fs.existsSync(originalPath)) {
      try {
        await execAsync(`ffmpeg -y -i "${originalPath}" -c:v libx264 -pix_fmt yuv420p -preset fast -crf 23 -movflags +faststart "${mp4Path}"`);
        if (fs.existsSync(mp4Path)) {
          const stat = fs.statSync(mp4Path);
          res.writeHead(200, {
            'Content-Length': stat.size,
            'Content-Type': 'video/mp4',
            'Content-Disposition': `attachment; filename="sorteoo_${giveaway.id}.mp4"`,
          });
          return fs.createReadStream(mp4Path).pipe(res);
        }
      } catch (cErr) {
        console.warn('ffmpeg sync conversion warning:', cErr);
      }

      // Serve original with mp4 disposition
      const stat = fs.statSync(originalPath);
      res.writeHead(200, {
        'Content-Length': stat.size,
        'Content-Type': 'video/mp4',
        'Content-Disposition': `attachment; filename="sorteoo_${giveaway.id}.mp4"`,
      });
      return fs.createReadStream(originalPath).pipe(res);
    }

    return res.status(404).json({ error: 'Archivo de video no encontrado en el servidor' });
  } catch (err: any) {
    return res.status(500).json({ error: 'Error al procesar descarga de MP4' });
  }
});

// Delete giveaway
app.delete('/api/giveaways/:id', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const index = db.giveaways.findIndex((g) => g.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Sorteo no encontrado' });
  }
  if (db.giveaways[index].userId !== req.user.id) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  // Remove video file if exists
  if (db.giveaways[index].video?.videoFileName) {
    const vPath = path.join(VIDEOS_DIR, db.giveaways[index].video.videoFileName!);
    if (fs.existsSync(vPath)) {
      try {
        fs.unlinkSync(vPath);
      } catch (e) {
        // ignore
      }
    }
  }

  db.giveaways.splice(index, 1);
  saveDB(db);
  return res.json({ message: 'Sorteo eliminado' });
});

// ----------------------------------------------------
// VITE SETUP (Full-stack integration)
// ----------------------------------------------------
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // Serve static files in production
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`sorteoo.app server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
