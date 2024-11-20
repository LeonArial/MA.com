const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'ai-mysql.ns-pp0165xx.svc',
    user: 'root',
    password: 'vljgzdl6',
    database: 'admin_system',
    port: 3306
});

connection.connect(error => {
    if (error) {
        console.error('数据库连接失败');
        return;
    }
    console.log('数据库连接成功');
});

module.exports = connection; 