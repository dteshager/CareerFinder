#!/bin/bash
docker run --rm -it -v $PWD:/debug -e API_KEY=${API_KEY} -p 80:5000 flask-app /bin/bash

