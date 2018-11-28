#!/bin/bash

# https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elastic-stack-on-ubuntu-16-04


sudo apt-get update

# ============================================================
# install htop
sudo apt-get install htop -y

# ============================================================
# install nginx
sudo apt-get install nginx -y

# configuration for nginx
sudo tee /etc/nginx/sites-available/kibana.com <<EOF

server {
    listen 80;

    server_name kibana.com;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

EOF


sudo ln -s /etc/nginx/sites-available/kibana.com /etc/nginx/sites-enabled/kibana.com
sudo rm /etc/nginx/sites-available/default

# ============================================================
# install the Java Development Kit
# If there are more than one verison of jave intalled use the cmd to choose the java vserion:
# sudo update-alternatives --config java

sudo apt-get install openjdk-8-jdk -y

# ============================================================
# Installing and Configuring Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list

sudo apt-get update

# install elasticsearch
sudo apt-get install elasticsearch


# Once Elasticsearch is finished installing, use your preferred text editor to edit Elasticsearch's main configuration file, elasticsearch.yml
sudo vim /etc/elasticsearch/elasticsearch.yml
# add the "network.host: localhost" just below the "network.host:" line

# start and enable "elasticsearch"
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

# test the installation for elasticsearch
curl -X GET "localhost:9200"

# ============================================================
# Installing and Configuring the Kibana Dashboard

# create the administrative Kibana user and password
echo "kibanaadmin:`openssl passwd -apr1`" | sudo tee -a /etc/nginx/htpasswd.users

# install kibana
sudo apt-get install kibana

# start and enable "kibana"
sudo systemctl enable kibana
sudo systemctl start kibana

# restart nginx
sudo systemctl restart nginx

# ============================================================
# Installing and Configuring Logstash

sudo apt-get install logstash -y


# INPUT logs
# specifies a beats input that will listen on TCP port 5044
sudo tee /etc/logstash/conf.d/02-beats-input.conf <<EOF
input {
  beats {
    port => 5044
  }
}

EOF

# FILTER logs
# filter for system logs, also known as "syslogs"
sudo tee /etc/logstash/conf.d/10-syslog-filter.conf <<EOF
filter {
  if [fileset][module] == "system" {
    if [fileset][name] == "auth" {
      grok {
        match => { "message" => ["%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} %{DATA:[system][auth][ssh][method]} for (invalid user )?%{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]} port %{NUMBER:[system][auth][ssh][port]} ssh2(: %{GREEDYDATA:[system][auth][ssh][signature]})?",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} user %{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: Did not receive identification string from %{IPORHOST:[system][auth][ssh][dropped_ip]}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sudo(?:\[%{POSINT:[system][auth][pid]}\])?: \s*%{DATA:[system][auth][user]} :( %{DATA:[system][auth][sudo][error]} ;)? TTY=%{DATA:[system][auth][sudo][tty]} ; PWD=%{DATA:[system][auth][sudo][pwd]} ; USER=%{DATA:[system][auth][sudo][user]} ; COMMAND=%{GREEDYDATA:[system][auth][sudo][command]}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} groupadd(?:\[%{POSINT:[system][auth][pid]}\])?: new group: name=%{DATA:system.auth.groupadd.name}, GID=%{NUMBER:system.auth.groupadd.gid}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} useradd(?:\[%{POSINT:[system][auth][pid]}\])?: new user: name=%{DATA:[system][auth][user][add][name]}, UID=%{NUMBER:[system][auth][user][add][uid]}, GID=%{NUMBER:[system][auth][user][add][gid]}, home=%{DATA:[system][auth][user][add][home]}, shell=%{DATA:[system][auth][user][add][shell]}$",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} %{DATA:[system][auth][program]}(?:\[%{POSINT:[system][auth][pid]}\])?: %{GREEDYMULTILINE:[system][auth][message]}"] }
        pattern_definitions => {
          "GREEDYMULTILINE"=> "(.|\n)*"
        }
        remove_field => "message"
      }
      date {
        match => [ "[system][auth][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
      }
      geoip {
        source => "[system][auth][ssh][ip]"
        target => "[system][auth][ssh][geoip]"
      }
    }
    else if [fileset][name] == "syslog" {
      grok {
        match => { "message" => ["%{SYSLOGTIMESTAMP:[system][syslog][timestamp]} %{SYSLOGHOST:[system][syslog][hostname]} %{DATA:[system][syslog][program]}(?:\[%{POSINT:[system][syslog][pid]}\])?: %{GREEDYMULTILINE:[system][syslog][message]}"] }
        pattern_definitions => { "GREEDYMULTILINE" => "(.|\n)*" }
        remove_field => "message"
      }
      date {
        match => [ "[system][syslog][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
      }
    }
  }
}

EOF

sudo tee /etc/logstash/conf.d/30-elasticsearch-output.conf <<EOF
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    manage_template => false
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
  }
}

EOF

# Test your Logstash configuration with this command:
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t

# ============================================================
# Here are the Beats that are currently available from Elastic:

# ==> Filebeat:   collects and ships log files.
# ==> Metricbeat: collects metrics from your systems and services.
# ==> Packetbeat: collects and analyzes network data.
# ==> Winlogbeat: collects Windows event logs.
# ==> Auditbeat:  collects Linux audit framework data and monitors file integrity.
# ==> Heartbeat:  monitors services for their availability with active probing.
# ============================================================

# Installing and Configuring Filebeat

# COMMENT OUT the "elasticsearch" the enable "logstash"
# sudo vim /etc/filebeat/filebeat.yml


# commented out:

# ...
# #output.elasticsearch:
#   # Array of hosts to connect to.
#   #hosts: ["localhost:9200"]
# ...

# uncommented:
# . . .
# output.logstash:
#   # The Logstash hosts
#   hosts: ["localhost:5044"]
# . . .

# Let's enable it:
sudo filebeat modules enable system

# list of enabled and disabled modules by running:
sudo filebeat modules list



# To load the template, use the following command:
# Next, load the index template into Elasticsearch. An Elasticsearch index is a collection of documents that have similar characteristics. Indexes are identified with a name, which is used to refer to the index when performing various operations within it. The index template will be automatically applied when a new index is created.
sudo filebeat setup --template -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["localhost:9200"]'


# As the dashboards load, Filebeat connects to Elasticsearch to check version information. To load dashboards when Logstash is enabled, you need to disable the Logstash output and enable Elasticsearch output:
sudo filebeat setup -e -E output.logstash.enabled=false -E output.elasticsearch.hosts=['localhost:9200'] -E setup.kibana.host=localhost:5601


# Now you can start and enable Filebeat:
sudo systemctl start filebeat
sudo systemctl enable filebeat


# To verify that Elasticsearch is indeed receiving this data, query the Filebeat index with this command:
curl -XGET 'http://localhost:9200/filebeat-*/_search?pretty'
