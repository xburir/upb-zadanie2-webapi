# Development
1. Start virtual environment with `source myproject/bin/activate`
2. Install dependencies with `pip install -r requirements.txt`
3. Run development server by running shell script `./server-debug.sh`, should be inside the bin folder when calling the script


sudo apt install default-libmysqlclient-dev
pip install pathlib
pip3 install flask_mysqldb
pip instlal bcrypt
pip3 install bcrypt
pip3 install pytz


mysql:

        CREATE DATABASE IF NOT EXISTS UPB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        CREATE USER IF NOT EXISTS 'admin'@'localhost' IDENTIFIED BY 'admin';
        GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost';
        FLUSH PRIVILEGES;


        CREATE TABLE `users` (
            `id` INT unsigned NOT NULL AUTO_INCREMENT,
            `firstName` VARCHAR(20) NOT NULL,
            `lastName` VARCHAR(20) NOT NULL,
            `email` VARCHAR(30) NOT NULL UNIQUE,
            `hashed_pass` TEXT NOT NULL,
            `salt` TEXT NOT NULL,
            `userName` VARCHAR(20) NOT NULL UNIQUE,
            PRIMARY KEY (`id`)
        );

v app.py zmenit nastavenia databazy:
    user: admin
    heslo: admin
    host: localhost