const mysql = require('mysql2');
const crypto = require('crypto');

const connection = mysql.createConnection({
    host: 'ai-mysql.ns-pp0165xx.svc',
    user: 'root',
    password: 'vljgzdl6',
    database: 'admin_system'
});

async function initAdmin() {
    try {
        // 首先修改表结构
        connection.query('ALTER TABLE users MODIFY COLUMN password VARCHAR(255)', (error) => {
            if (error) {
                console.error('修改表结构失败：', error);
                connection.end();
                return;
            }
            console.log('密码字段长度已更新');

            // 使用 SHA-256 哈希密码
            const hashedPassword = crypto.createHash('sha256').update('admin123').digest('hex');
            console.log('初始化的密码哈希值：', hashedPassword);
            
            // 检查是否已存在 admin 用户
            connection.query('SELECT id, password FROM users WHERE username = ?', ['admin'], (error, results) => {
                if (error) {
                    console.error('查询失败：', error);
                    connection.end();
                    return;
                }

                console.log('查询现有用户结果：', results);

                if (results.length > 0) {
                    console.log('更新现有管理员用户');
                    connection.query(
                        'UPDATE users SET password = ?, role = ? WHERE username = ?',
                        [hashedPassword, 'admin', 'admin'],
                        (error) => {
                            if (error) {
                                console.error('更新管理员失败：', error);
                            } else {
                                console.log('管理员密码已更新为：', hashedPassword);
                            }
                            connection.end();
                        }
                    );
                } else {
                    console.log('创建新管理员用户');
                    connection.query(
                        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                        ['admin', hashedPassword, 'admin'],
                        (error) => {
                            if (error) {
                                console.error('创建管理员失败：', error);
                            } else {
                                console.log('管理员账户已创建，密码为：', hashedPassword);
                            }
                            connection.end();
                        }
                    );
                }
            });
        });
    } catch (error) {
        console.error('初始化管理员失败：', error);
        connection.end();
    }
}

initAdmin(); 