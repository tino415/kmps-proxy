#! /bin/bash
apt-get update
yes | apt-get install php5 php5-mcrypt php5-dev php-pear
pecl install pthreads
