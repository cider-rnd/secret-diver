FROM alpine:latest

RUN echo "AWS_SECRET=test123456" > /tmp/.pypirc

RUN rm /tmp/.pypirc

CMD ["echo all is good"]