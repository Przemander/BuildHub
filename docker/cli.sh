#Install project
if echo "$1" | grep -iq "install" ;then
  eval "docker-compose up --build -d"
fi