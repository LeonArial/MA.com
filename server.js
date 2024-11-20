const express = require('express');
const session = require('express-session');
const path = require('path');
const db = require('./db');
const bcrypt = require('bcryptjs');
const http = require('http');
const socketIo = require('socket.io');
const svgCaptcha = require('svg-captcha');
const multer = require('multer');
const fs = require('fs');

const app = express();

// 配置文件上传
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'public/uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024
    }
});

// 配置中间件
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'your-secret-key',
    resave: true,
    saveUninitialized: true,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
        name: 'sessionId',
        rolling: true,
    }
}));

// 检查登录状态的中间件
const checkAuth = (req, res, next) => {
    if (req.session.userId) {
        // 检查是否是活跃会话
        const currentActiveSession = activeUserSessions.get(req.session.userId);
        if (currentActiveSession === req.sessionID) {
            next();
        } else {
            res.status(401).json({
                success: false,
                message: '您的账号已在其他地方登录'
            });
        }
    } else {
        res.redirect('/login');
    }
};

// 检查管理员权限的中间件
const checkAdmin = (req, res, next) => {
    if (req.session.userRole === 'admin') {
        next();
    } else {
        res.status(403).json({
            success: false,
            message: '需要管理员权限'
        });
    }
};

// 路由处理
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/admin', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// 创建 HTTP 服务器
const server = http.createServer(app);
const io = socketIo(server);

// 添加登录失败次数记录
const loginAttempts = new Map();

// 在文件顶部添加用户会话跟踪
const activeUserSessions = new Map();

// Socket.IO 连接处理
io.on('connection', (socket) => {
    // 只在用户登录时记录
    socket.on('store_user_socket', (userId) => {
        if (userId) {
            socket.userId = userId;
        }
    });

    socket.on('disconnect', () => {
        const userId = socket.userId;
        if (userId) {
            socket.userId = null;
        }
    });
});

// 登录状态检查
app.get('/api/login/status', (req, res) => {
    if (req.session.userId) {
        res.json({
            success: true,
            user: {
                id: req.session.userId,
                username: req.session.username,
                role: req.session.userRole
            }
        });
    } else {
        res.json({
            success: false,
            message: '未登录'
        });
    }
});

// 登录处理
app.post('/api/login', async (req, res) => {
    const { username, password, captcha } = req.body;
    
    // 验证码验证
    const storedCaptcha = req.session.captchaText;
    const inputCaptcha = (captcha || '').toLowerCase();

    if (!storedCaptcha || storedCaptcha !== inputCaptcha) {
        return res.status(400).json({
            success: false,
            message: '验证码错误'
        });
    }

    delete req.session.captchaText;
    
    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], async (error, results) => {
        if (error) {
            return res.status(500).json({ 
                success: false, 
                message: '服务器错误' 
            });
        }

        if (results.length > 0) {
            const user = results[0];
            
            if (password === user.password) {
                // 检查用户是否已在其他地方登录
                const existingSessionId = activeUserSessions.get(user.id);
                if (existingSessionId && existingSessionId !== req.sessionID) {
                    // 通过用户ID找到对应的socket并发送强制登出消息
                    const existingSocket = userSocketMap.get(user.id);
                    if (existingSocket) {
                        existingSocket.emit('force_logout', {
                            message: '您的账号已在其他设备登录'
                        });
                    }

                    // 强制注销已登录的会话
                    try {
                        await new Promise((resolve) => {
                            req.sessionStore.destroy(existingSessionId, (err) => {
                                if (err) {
                                    console.error('会话注销失败');
                                }
                                resolve();
                            });
                        });
                    } catch (err) {
                        console.error('强制注销会话失败');
                    }
                }

                // 更新活跃会话记录
                activeUserSessions.set(user.id, req.sessionID);
                
                // 设置会话
                req.session.userId = user.id;
                req.session.username = user.username;
                req.session.userRole = user.role;
                
                res.json({
                    success: true,
                    message: '登录成功',
                    user: {
                        id: user.id,
                        username: user.username,
                        role: user.role
                    }
                });
            } else {
                res.status(401).json({
                    success: false,
                    message: '密码错误'
                });
            }
        } else {
            res.status(401).json({
                success: false,
                message: '用户不存在'
            });
        }
    });
});

// 登出处理
app.post('/api/logout', (req, res) => {
    if (req.session.userId) {
        activeUserSessions.delete(req.session.userId);
    }
    
    req.session.destroy((err) => {
        if (err) {
            console.error('注销失败');
            return res.status(500).json({
                success: false,
                message: '注销失败'
            });
        }
        res.json({
            success: true,
            message: '注销成功'
        });
    });
});

// 获取用户列表
app.get('/api/users', checkAuth, checkAdmin, (req, res) => {
    db.query('SELECT * FROM users', (error, results) => {
        if (error) {
            return res.status(500).json({
                success: false,
                message: '获取用户列表失败'
            });
        }
        res.json({
            success: true,
            users: results
        });
    });
});

// 添加用户
app.post('/api/users', checkAuth, checkAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    
    if (!username || !password || !role) {
        return res.status(400).json({
            success: false,
            message: '缺少必要参数'
        });
    }

    try {
        const checkUser = await new Promise((resolve, reject) => {
            db.query('SELECT id FROM users WHERE username = ?', [username], (error, results) => {
                if (error) reject(error);
                resolve(results);
            });
        });

        if (checkUser.length > 0) {
            return res.status(400).json({
                success: false,
                message: '用户名已存在'
            });
        }

        const query = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
        db.query(query, [username, password, role], (error, results) => {
            if (error) {
                return res.status(500).json({
                    success: false,
                    message: '添加用户失败'
                });
            }
            res.json({
                success: true,
                message: '用户添加成功',
                userId: results.insertId
            });
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: '服务器错误'
        });
    }
});

// 更新用户
app.put('/api/users/:id', checkAuth, checkAdmin, async (req, res) => {
    const { id } = req.params;
    const { username, password, role } = req.body;
    
    try {
        let query = 'UPDATE users SET ';
        const params = [];
        
        if (username) {
            query += 'username = ?';
            params.push(username);
        }
        
        if (password) {
            if (username) query += ', ';
            query += 'password = ?';
            params.push(password);
        }

        if (role) {
            if (username || password) query += ', ';
            query += 'role = ?';
            params.push(role);
        }
        
        query += ' WHERE id = ?';
        params.push(id);

        db.query(query, params, (error) => {
            if (error) {
                return res.status(500).json({
                    success: false,
                    message: '更新用户失败'
                });
            }
            res.json({
                success: true,
                message: '用户更新成功'
            });
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: '服务器错误'
        });
    }
});

// 删除用户
app.delete('/api/users/:id', checkAuth, (req, res) => {
    const { id } = req.params;
    
    db.query('DELETE FROM users WHERE id = ?', [id], (error) => {
        if (error) {
            return res.status(500).json({
                success: false,
                message: '删除用户失败'
            });
        }
        res.json({
            success: true,
            message: '用户删除成功'
        });
    });
});

// 添加仪表盘数据接口
app.get('/api/dashboard', checkAuth, async (req, res) => {
    try {
        // 获取用户总数和管理员数量
        const [totalUsers] = await db.promise().query('SELECT COUNT(*) as count FROM users');
        const [adminUsers] = await db.promise().query('SELECT COUNT(*) as count FROM users WHERE role = "admin"');
        
        // 获取最近30天活跃用户数（这里用登录时间来模拟，实际应该根据具体需求修改）
        const [activeUsers] = await db.promise().query(
            'SELECT COUNT(DISTINCT user_id) as count FROM user_logins WHERE login_time > DATE_SUB(NOW(), INTERVAL 30 DAY)'
        );

        res.json({
            success: true,
            totalUsers: totalUsers[0].count,
            totalAdmins: adminUsers[0].count,
            activeUsers: activeUsers[0].count || 0
        });
    } catch (error) {
        console.error('获取仪表盘数据失败：', error);
        res.status(500).json({
            success: false,
            message: '获取仪表盘数据失败'
        });
    }
});

// 添加验证码接口
app.get('/api/captcha', (req, res) => {
    const captcha = svgCaptcha.create({
        size: 4,
        noise: 2,
        color: true,
        background: '#f0f0f0',
        width: 120,
        height: 40,
        fontSize: 40,
        ignoreChars: '0o1ilI'
    });

    req.session.captchaText = captcha.text.toLowerCase();
    
    res.type('svg');
    res.status(200).send(captcha.data);
});

// 图片上传接口
app.post('/api/upload', checkAuth, upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({
            success: false,
            message: '没有上传文件'
        });
    }

    res.json({
        success: true,
        url: `/uploads/${req.file.filename}`
    });
});

// 获取内容列表
app.get('/api/contents', checkAuth, async (req, res) => {
    try {
        const [contents] = await db.promise().query(
            'SELECT * FROM contents ORDER BY created_at DESC'
        );
        res.json({
            success: true,
            contents
        });
    } catch (error) {
        console.error('获取内容列表失败：', error);
        res.status(500).json({
            success: false,
            message: '获取内容列表失败'
        });
    }
});

// 获取公开内容
app.get('/api/public/contents', async (req, res) => {
    try {
        let query = `
            SELECT c.*, u.username as author 
            FROM contents c 
            LEFT JOIN users u ON c.created_by = u.id 
            WHERE c.status = 'published'
        `;
        
        const params = [];
        
        if (req.query.category && req.query.category !== 'all') {
            query += ' AND c.category = ?';
            params.push(req.query.category);
        }
        
        query += ' ORDER BY c.created_at DESC';
        
        const [contents] = await db.promise().query(query, params);
        
        res.json({
            success: true,
            contents
        });
    } catch (error) {
        console.error('获取公开内容列表失败：', error);
        res.status(500).json({
            success: false,
            message: '获取内容列表失败'
        });
    }
});

// 添加新内容
app.post('/api/contents', checkAuth, async (req, res) => {
    const { title, category, content, status } = req.body;
    
    try {
        const [result] = await db.promise().query(
            'INSERT INTO contents (title, category, content, status, created_by) VALUES (?, ?, ?, ?, ?)',
            [title, category, content, status, req.session.userId]
        );
        
        res.json({
            success: true,
            message: '内容添加成功',
            contentId: result.insertId
        });
    } catch (error) {
        console.error('添加内容失败：', error);
        res.status(500).json({
            success: false,
            message: '添加内容失败'
        });
    }
});

// 更新内容
app.put('/api/contents/:id', checkAuth, async (req, res) => {
    const { id } = req.params;
    const { title, category, content, status } = req.body;
    
    try {
        await db.promise().query(
            'UPDATE contents SET title = ?, category = ?, content = ?, status = ?, updated_at = NOW() WHERE id = ?',
            [title, category, content, status, id]
        );
        
        res.json({
            success: true,
            message: '内容更新成功'
        });
    } catch (error) {
        console.error('更新内容失败：', error);
        res.status(500).json({
            success: false,
            message: '更新内容失败'
        });
    }
});

// 删除内容
app.delete('/api/contents/:id', checkAuth, async (req, res) => {
    const { id } = req.params;
    
    try {
        await db.promise().query('DELETE FROM contents WHERE id = ?', [id]);
        
        res.json({
            success: true,
            message: '内容删除成功'
        });
    } catch (error) {
        console.error('删除内容失败：', error);
        res.status(500).json({
            success: false,
            message: '删除内容失败'
        });
    }
});

server.listen(3000, () => {
    console.log('服务器运行在 http://localhost:3000/');
});

// ... 其他代码 ... 