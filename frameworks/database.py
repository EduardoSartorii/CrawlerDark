import sqlite3
import os


class Database:
    def __init__(self,database_path=None, database_name=None):
        self.database_path = database_path
        self.database_name = database_name
        self.dir_db = f'{self.database_path}/{self.database_name}'

        if not os.path.exists(self.dir_db):
            conn = sqlite3.connect(self.dir_db)
            cursor = conn.cursor()

            cursor.execute('CREATE TABLE IF NOT EXISTS leak (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
            'enterprise TEXT, data TEXT NOT NULL);')
            conn.commit()
            conn.close()
        else:
            conn = sqlite3.connect(self.dir_db)
            cursor = conn.cursor()

            cursor.execute('CREATE TABLE IF NOT EXISTS leak (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
            'enterprise TEXT, data TEXT NOT NULL);')
            conn.commit()
            conn.close()
        
    def save(self,data:str, enterprise:str) -> bool:
        try:
            conn = sqlite3.connect(self.dir_db)
            cursor = conn.cursor()
            cursor.execute("""INSERT INTO leak (data, enterprise)VALUES ('%s','%s');"""%(data,enterprise))
            conn.commit()
            conn.close()
            return True
        except Exception as error:
            return error

    def compare(self,data:str, enterprise:str) -> bool:
            try:
                conn = sqlite3.connect(self.dir_db)
                cursor = conn.cursor()

                compare = cursor.execute(f"SELECT * FROM leak WHERE data = '{data}' AND enterprise = '{enterprise}';")
                return compare.fetchall()
            except Exception as e:
                print(f"[ERROR]Não foi possível comparar a informação no banco de dados pelo motivo: {e}")
                return False