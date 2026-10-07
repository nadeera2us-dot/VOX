const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;

app.use(express.json({limit:"1mb"}));
app.use(express.static(path.join(__dirname, "public")));

const hash = function (value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
};

const cleanPhone = function (value) {
  return String(value || "").trim().replace(/[^0-9+]/g, "");
};

const users = [
  {id:"admin", name:"Admin", phone:"admin", password:hash(process.env.ADMIN_PASSWORD || "admin123"), role:"admin", active:true},
  {id:"u1", name:"Luca", phone:"3330000001", password:hash("voxo123"), role:"user", active:true},
  {id:"u2", name:"Marco", phone:"3330000002", password:hash("voxo123"), role:"user", active:true},
  {id:"u3", name:"Sara", phone:"3330000003", password:hash("voxo123"), role:"user", active:true},
  {id:"u4", name:"Giulia", phone:"3330000004", password:hash("voxo123"), role:"user", active:true},
  {id:"u5", name:"Andrea", phone:"3330000005", password:hash("voxo123"), role:"user", active:true}
];

const sessions = new Map();
const messages = [];
const bannedWords = ["cazzo","merda","stronzo","stronza","coglione","cogliona","vaffanculo"];

function publicUser(user) {
  return {
    id:user.id,
    name:user.name,
    phone:user.phone,
    role:user.role,
    active:user.active
  };
}

function censor(text) {
  let output = String(text || "");
  for (const word of bannedWords) {
    const re = new RegExp("\\b" + word + "\\b", "gi");
    output = output.replace(re, "*".repeat(Math.max(3, word.length)));
  }
  return output.slice(0,1000);
}

function getSession(req) {
  const token = String(req.headers.authorization || "").replace("Bearer ","");
  return sessions.get(token);
}

function requireAuth(req,res,next) {
  const session = getSession(req);
  if (!session) return res.status(401).json({error:"Non autorizzato"});
  req.session = session;
  next();
}

function requireAdmin(req,res,next) {
  const session = getSession(req);
  if (!session || session.role !== "admin") return res.status(403).json({error:"Solo Admin"});
  req.session = session;
  next();
}

app.get("/api/health", function (req,res) {
  res.json({ok:true, site:"VOXO.COM"});
});

app.post("/api/login", function (req,res) {
  const phone = cleanPhone(req.body.phone);
  const password = hash(req.body.password || "");
  const user = users.find(function (item) {
    return item.phone === phone && item.active && item.password === password;
  });
  if (!user) return res.status(401).json({error:"Numero/utente o password non validi."});
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {id:user.id,name:user.name,phone:user.phone,role:user.role});
  res.json({token:token,user:publicUser(user)});
});

app.get("/api/me", requireAuth, function (req,res) {
  const user = users.find(function (item) { return item.id === req.session.id; });
  res.json({user:publicUser(user)});
});

app.get("/api/messages", requireAuth, function (req,res) {
  res.json(messages.slice(-200));
});

app.post("/api/messages", requireAuth, function (req,res) {
  const message = {
    id: crypto.randomUUID(),
    userId: req.session.id,
    userName: req.session.name,
    text: censor(req.body.text),
    createdAt: new Date().toISOString()
  };
  if (!message.text.trim()) return res.status(400).json({error:"Messaggio vuoto"});
  messages.push(message);
  if (messages.length > 1000) messages.shift();
  io.emit("new-message", message);
  res.json(message);
});

app.get("/api/users", requireAdmin, function (req,res) {
  res.json(users.map(publicUser));
});

app.post("/api/users", requireAdmin, function (req,res) {
  const name = String(req.body.name || "").trim().slice(0,40);
  const phone = cleanPhone(req.body.phone);
  const password = String(req.body.password || "");
  if (!name || !phone || password.length < 6) {
    return res.status(400).json({error:"Nome, numero e password di almeno 6 caratteri sono obbligatori."});
  }
  if (users.some(function (item) { return item.phone === phone; })) {
    return res.status(409).json({error:"Numero già esistente."});
  }
  const user = {
    id: crypto.randomUUID(),
    name:name,
    phone:phone,
    password:hash(password),
    role:"user",
    active:true
  };
  users.push(user);
  res.json(publicUser(user));
});

app.patch("/api/users/:id", requireAdmin, function (req,res) {
  const user = users.find(function (item) { return item.id === req.params.id; });
  if (!user) return res.status(404).json({error:"Utente non trovato"});
  if (req.body.name !== undefined) user.name = String(req.body.name).trim().slice(0,40);
  if (req.body.phone !== undefined) {
    const phone = cleanPhone(req.body.phone);
    if (users.some(function (item) { return item.id !== user.id && item.phone === phone; })) {
      return res.status(409).json({error:"Numero già esistente."});
    }
    user.phone = phone;
  }
  if (req.body.password) {
    const password = String(req.body.password);
    if (password.length < 6) return res.status(400).json({error:"Password troppo corta"});
    user.password = hash(password);
  }
  if (req.body.active !== undefined && user.role !== "admin") {
    user.active = !!req.body.active;
  }
  res.json(publicUser(user));
});

app.delete("/api/users/:id", requireAdmin, function (req,res) {
  const index = users.findIndex(function (item) {
    return item.id === req.params.id && item.role !== "admin";
  });
  if (index < 0) return res.status(404).json({error:"Utente non trovato"});
  users.splice(index,1);
  res.json({ok:true});
});

io.on("connection", function (socket) {
  socket.on("register", function (token) {
    const session = sessions.get(token);
    if (session) socket.user = session;
  });

  socket.on("voice-offer", function (data) {
    socket.to(data.target).emit("voice-offer", {
      from:socket.id,
      offer:data.offer,
      user:socket.user || null
    });
  });

  socket.on("voice-answer", function (data) {
    socket.to(data.target).emit("voice-answer", {
      from:socket.id,
      answer:data.answer
    });
  });

  socket.on("voice-candidate", function (data) {
    socket.to(data.target).emit("voice-candidate", {
      from:socket.id,
      candidate:data.candidate
    });
  });
});

app.get("*", function (req,res) {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

server.listen(PORT, "0.0.0.0", function () {
  console.log("VOXO.COM listening on " + PORT);
});
