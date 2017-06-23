# cryptography-demo

a very sample demo that deal with RSA task using cryptography in python3 

一个十分简单的在Python3中使用cryptography库进行RSA加密的demo


### 公私钥生成说明

##### 使用openssl工具生成公私钥

1. 生成RSA私钥 

```
genrsa -out rsa_private_key.pem 1024
```

2. 生成公钥

```
rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
```
