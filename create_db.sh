rm -f $1
sqlite3 $1 < schema.sql
