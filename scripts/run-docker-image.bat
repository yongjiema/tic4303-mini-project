@echo off

type nul > database.sqlite
docker run ^
    -it ^
    -p 0.0.0.0:3000:3000 ^
    -v "%cd%\database.sqlite:/data/database.sqlite" ^
    -e DATABASE_PATH=/data/database.sqlite ^
    tic4303-mini-project
