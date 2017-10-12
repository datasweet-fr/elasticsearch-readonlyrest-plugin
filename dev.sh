#!/bin/bash

# ATTENTION ! Si vous changez le dossier penser à changer également dans ./dev/elasticsearch.yml
ES_DIR=/Users/tcharlot/Downloads/elasticsearch-5.6.2
source  ./dev/read_ini.sh
read_ini ./gradle.properties

./gradlew ror

#pkill  -f elasticsearch
$ES_DIR/bin/elasticsearch-plugin remove ${INI__pluginName}
$ES_DIR/bin/elasticsearch-plugin install file://$PWD/build/distributions/${INI__pluginName}-${INI__pluginVersion}_es${INI__esVersion}.zip
cp -f ./dev/elasticsearch.yml $ES_DIR/config/
cp -f ./dev/elasticsearch-ror.yml $ES_DIR/config/
$ES_DIR/bin/elasticsearch

# NOTE : si ca se lance pa (java security secret), ne pas oublier de mettre à jour les jar dans le $JAVA_HOME