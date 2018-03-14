import MySQLdb

def connection():
    conn = MySQLdb.connect(host="localhost",
                            user="root",
                            passwd="nandakishor",
                            db="freebooter")
    c = conn.cursor()
    return c, conn
