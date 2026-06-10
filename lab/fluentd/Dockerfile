# Fluentd image with the Elasticsearch output plugin.
#
# Build:  docker build -t qob/fluentd-es:latest lab/fluentd
FROM fluent/fluentd:v1.17-1

USER root
RUN gem install fluent-plugin-elasticsearch --no-document \
    && gem sources --clear-all
USER fluent
