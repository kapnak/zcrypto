mkdir -p build
cd build || exit
pkg ../src/cli.js -t node18-linux,node18-win
mv cli-linux zcrypto
mv cli-win.exe zcrypto.exe
