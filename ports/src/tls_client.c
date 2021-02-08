/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rtthread.h>

#include "tls_client.h"
#include "tls_certificate.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_DEBUG_C)
#define DEBUG_LEVEL (2)
#endif

#define DBG_ENABLE
#define DBG_COLOR
#define DBG_SECTION_NAME    "mbedtls.clnt"
#ifdef MBEDTLS_DEBUG_C
#define DBG_LEVEL           DBG_LOG
#else
#define DBG_LEVEL           DBG_INFO
#endif /* MBEDTLS_DEBUG_C */
#include <rtdbg.h>

static void _ssl_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);

    LOG_D("%s:%04d: %s", file, line, str);
}

/**
 * @brief 获取证书验证结果
 * 
 * @param session 会话对象
 */
static int mbedtls_ssl_certificate_verify(MbedTLSSession *session)
{
    int ret = 0;

    // 获取证书验证结果
    ret = mbedtls_ssl_get_verify_result(&session->ssl);

    if (ret != 0)
    {
        LOG_E("verify peer certificate fail....");
        memset(session->buffer, 0x00, session->buffer_len);

        // 证书验证结果的 API 接口，具体的错误信息
        // 返回： 写入的字符串的长度（不包括结束符）或负的错误代码
        mbedtls_x509_crt_verify_info((char *)session->buffer,   // 存储验证状态信息字符串的缓冲区
                                     session->buffer_len,       // 缓冲区大小
                                     "  ! ",                    // 行前缀
                                     ret);                      // 由 mbedtls_x509_crt_verify_info 函数返回的值

        LOG_E("verification info: %s", session->buffer);
        return -RT_ERROR;
    }
    return RT_EOK;
}


/**
 * @brief mbedtls 初始化
 * mbedtls 客户端初始化函数，用于初始化底层网络接口、设置证书、设置 SSL 会话等。
 * 
 * @param session 入参，mbedtls 会话对象 MbedTLSSession
 * @param entropy 入参，mbedtls 熵字符串
 * @param entropyLen 入参，mbedtls 熵字符串长度
 * 
 * @return 0 成功  !0失败
 */
int mbedtls_client_init(MbedTLSSession *session, void *entropy, size_t entropyLen)
{
    int ret = 0;

    // 如需调试log，则启用
#if defined(MBEDTLS_DEBUG_C)
    LOG_D("Set debug level (%d)", (int) DEBUG_LEVEL);
    
    // 设置调试级别
    // 如果开启了 `MBEDTLS_DEBUG_C`，可以使用该函数设置调试级别，用于控制不同级别的调试日志输出。
    mbedtls_debug_set_threshold((int) DEBUG_LEVEL); 
#endif

    mbedtls_net_init(&session->server_fd);      // (mbedtls内部函数，port层重新实现)初始化 TLS 网络上下文，目前只有 fd 描述符
    mbedtls_ssl_init(&session->ssl);            // (mbedtls内部函数)SSL 上下文初始化，主要是清空 SSL 上下文对象，为 SSL 连接做准备。
    mbedtls_ssl_config_init(&session->conf);    // (mbedtls内部函数)SSL 配置初始化，主要是清空 SSL 配置结构体对象，为 SSL 连接做准备
    mbedtls_ctr_drbg_init(&session->ctr_drbg);  // (mbedtls内部函数)清空 CTR_DRBG（SSL 随机字节发生器）上下文结构体对象，为 `mbedtls_ctr_drbg_seed` 做准备
    mbedtls_entropy_init(&session->entropy);    // (mbedtls内部函数)初始化 SSL 熵结构体对象
    mbedtls_x509_crt_init(&session->cacert);    // (mbedtls内部函数)设置根证书列表, 初始化根证书链表，主要是清空
    
    // （mbedtls内部函数）为 SSL/TLS 熵设置熵源，方便产生子种子
    ret = mbedtls_ctr_drbg_seed(&session->ctr_drbg,         // CTR_DRBG 结构体对象
                                mbedtls_entropy_func,       // (mbedtls内部函数)熵回调
                                &session->entropy,          // 熵结构体（mbedtls_entropy_context）对象
                                (unsigned char *)entropy,   // 个性化数据（设备特定标识符），可以为空
                                entropyLen);                // 个性化数据长度
    if (ret != 0)
    {
        LOG_E("mbedtls_ctr_drbg_seed error, return -0x%x\n", -ret);
        return ret;
    }
    LOG_D("mbedtls client struct init success...");

    return RT_EOK;
}

/**
 * @brief 关闭 mbedtls 客户端
 * 客户端主动关闭连接或者因为异常错误关闭连接，都需要使用 mbedtls_client_close 关闭连接并释放资源
 * 
 * @param session 入参，mbedtls 会话对象 MbedTLSSession
 * 
 * @return 0 成功  !0失败
 */
int mbedtls_client_close(MbedTLSSession *session)
{
    if (session == RT_NULL)
    {
        return -RT_ERROR;
    }

    mbedtls_ssl_close_notify(&session->ssl);        // (mbedtls内部函数) 通知对方连接已关闭
    mbedtls_net_free(&session->server_fd);          // (mbedtls内部函数，外部重新实现) 关闭套接口
    mbedtls_x509_crt_free(&session->cacert);        // (mbedtls内部函数) 释放分配所有证书数据
    mbedtls_entropy_free(&session->entropy);        // (mbedtls内部函数) 释放 SSL 熵结构体对象
    mbedtls_ctr_drbg_free(&session->ctr_drbg);      // (mbedtls内部函数) 释放 CTR_DRBG（SSL 随机字节发生器）上下文结构体对象
    mbedtls_ssl_config_free(&session->conf);        // (mbedtls内部函数) 释放 SSL 配置
    mbedtls_ssl_free(&session->ssl);                // (mbedtls内部函数) 释放 SSL 上下文对象

    if (session->buffer)
    {
        tls_free(session->buffer);
    }

    if (session->host)
    {
        tls_free(session->host);
    }

    if(session->port)
    {
        tls_free(session->port);
    }

    if (session)
    {   
        tls_free(session);
        session = RT_NULL;
    }
    
    return RT_EOK;
}


/**
 * @brief 配置 mbedtls 上下文
 * SSL 层配置，应用程序使用 mbedtls_client_context 函数配置客户端上下文信息
 * 包括证书解析、设置主机名、设置默认 SSL 配置、设置认证模式（默认 MBEDTLS_SSL_VERIFY_OPTIONAL）等。
 * 
 * @param session 入参，mbedtls 会话对象 MbedTLSSession
 * 
 * @return 0 成功  !0失败
 */
int mbedtls_client_context(MbedTLSSession *session)
{
    int ret = 0;
    
    // 解析根证书
    // 解释性地解析。解析 buf 中一个或多个证书并将其添加到根证书链接列表中。
    // 如果可以解析某些证书，则结果是它遇到的失败证书的数量。 
    // 如果没有正确完成，则返回第一个错误
    // (mbedtls内部函数)
    ret = mbedtls_x509_crt_parse(&session->cacert,                                  // 入参，x509 证书结构体对象
                                 (const unsigned char *)mbedtls_root_certificate,   // 入参，存储根证书的 buffer，`mbedtls_root_certificate` 数组
                                 mbedtls_root_certificate_len);                     // 入参，存储根证书的 buffer 大小
    if (ret < 0)
    {
        LOG_E("mbedtls_x509_crt_parse error,  return -0x%x", -ret);
        return ret;
    }

    LOG_D("Loading the CA root certificate success...");

    /* Hostname set here should match CN in server certificate */
    // 此处设置的主机名应与服务器证书中的CN匹配
    if (session->host)
    {
        // 设置主机名
        // 这里设置的 `hostname` 必须对应服务器证书中的 `common name`，即 CN 字段
        ret = mbedtls_ssl_set_hostname(&session->ssl, session->host);
        if (ret != 0)
        {
            LOG_E("mbedtls_ssl_set_hostname error, return -0x%x", -ret);
            return ret;
        }
    }

    // (mbedtls内部函数)加载默认的 SSL 配置
    ret = mbedtls_ssl_config_defaults(&session->conf,                   // SSL 配置结构体对象
                                      MBEDTLS_SSL_IS_CLIENT,            // MBEDTLS_SSL_IS_CLIENT 或者 MBEDTLS_SSL_IS_SERVER
                                      MBEDTLS_SSL_TRANSPORT_STREAM,     // TLS:  MBEDTLS_SSL_TRANSPORT_STREAM
                                                                        // DTLS: MBEDTLS_SSL_TRANSPORT_DATAGRAM
                                      MBEDTLS_SSL_PRESET_DEFAULT);      // 预定义的 MBEDTLS_SSL_PRESET_XXX 类型值，
                                                                        // 默认使用 MBEDTLS_SSL_PRESET_DEFAULT
    if (ret != 0)
    {
        LOG_E("mbedtls_ssl_config_defaults error, return -0x%x", -ret);
        return ret;
    }

    // (mbedtls内部函数)设置证书验证模式
    // 服务器上为 `MBEDTLS_SSL_VERIFY_NONE`，
    // 客户端上为 `MBEDTLS_SSL_VERIFY_REQUIRED` 或者 `MBEDTLS_SSL_VERIFY_OPTIONAL`（默认使用）
    mbedtls_ssl_conf_authmode(&session->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    // 设置验证对等证书所需的数据
    // 将受信的证书链配置到 SSL 配置结构体对象中
    // (mbedtls内部函数)
    mbedtls_ssl_conf_ca_chain(&session->conf,       // SSL 配置结构体对象
                              &session->cacert,     // 受信的 CA 证书链，存储在 MbedTLSSession 的成员对象 cacert 中
                              NULL);                // 受信的 CA CRLs，可为空

    // 设置随机数生成器回调
    // (mbedtls内部函数)
    mbedtls_ssl_conf_rng(&session->conf,            // SSL 配置结构体对象
                         mbedtls_ctr_drbg_random,   // 随机数生成器函数
                         &session->ctr_drbg);       // 随机数生成器函数参数

    // (mbedtls内部函数)
    mbedtls_ssl_conf_dbg(&session->conf,            
                         _ssl_debug, 
                         NULL);

    // 设置 SSL 上下文
    // 将 SSL 配置结构体对象设置到 SSL 上下文中
    // (mbedtls内部函数)
    ret = mbedtls_ssl_setup(&session->ssl,          // SSL 上下文结构体对象
                            &session->conf);        // SSL 配置结构体对象
    if (ret != 0)
    {
        LOG_E("mbedtls_ssl_setup error, return -0x%x\n", -ret);
        return ret;
    }
    LOG_D("mbedtls client context init success...");

    return RT_EOK;
}

/**
 * @brief 建立 SSL/TLS 连接,这里包含整个的握手连接过程，以及证书校验结果。
 * SSL 层配置，应用程序使用 mbedtls_client_context 函数配置客户端上下文信息
 * 包括证书解析、设置主机名、设置默认 SSL 配置、设置认证模式（默认 MBEDTLS_SSL_VERIFY_OPTIONAL）等。
 * 
 * @param session 入参，mbedtls 会话对象 MbedTLSSession
 * 
 * @return 0 成功  !0失败
 */
int mbedtls_client_connect(MbedTLSSession *session)
{   
    int ret = 0;

    // 与给定的 `host`、`port` 及 `proto` 协议建立网络连接
    // 返回：`= 0`成功
    // `- 0x0042`socket 创建失败
    // `- 0x0052`未知的主机名，DNS 解析失败
    // `- 0x0044`网络连接失败
    // (mbedtls内部函数,port层重写改函数)
    ret = mbedtls_net_connect(&session->server_fd,      // NET 网络配置结构体对象
                              session->host,            // 指定的待连接主机名
                              session->port,            // 指定的主机端口号
                              MBEDTLS_NET_PROTO_TCP);   // 指定的协议类型，MBEDTLS_NET_PROTO_TCP 或者 MBEDTLS_NET_PROTO_UDP
    if (ret != 0)
    {
        LOG_E("mbedtls_net_connect error, return -0x%x", -ret);
        return ret;
    }

    LOG_D("Connected %s:%s success...", session->host, session->port);

    // 设置网络层读写接口，被 `mbedtls_ssl_read` 和 `mbedtls_ssl_write` 函数调用
    mbedtls_ssl_set_bio(&session->ssl,                  // SSL 上下文结构体对象
                        &session->server_fd,            // socket 描述符
                        mbedtls_net_send,               // 网络层写回调函数
                        mbedtls_net_recv,               // 网络层读回调函数，TLS使用该回调函数接受数据
                        NULL);                          // 网络层非阻塞带超时读回调函数，DTLS使用该回调接受数据，TLS也可以使用（如果recv和timeout都提供了）

    // 执行 SSL/TLS 握手操作
    // `= 0`成功`
    // MBEDTLS_ERR_SSL_WANT_READ             : SSL 客户端需要读取调用
    // MBEDTLS_ERR_SSL_WANT_WRITE            : SSL 客户端需要写入调用
    // MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED : DTLS 客户端必须重试才能进行 hello 验证
    // 其它       : SSL 指定的错误码
    // 如果使用的是 DTLS，需要单独处理 MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED 错误，因为它是预期的返回值而不是实际错误
    while ((ret = mbedtls_ssl_handshake(&session->ssl)) != 0)
    {
        if (RT_EOK != mbedtls_ssl_certificate_verify(session))
        {
            return -RT_ERROR;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            LOG_E("mbedtls_ssl_handshake error, return -0x%x", -ret);
            return ret;
        }
    }

    if (RT_EOK != mbedtls_ssl_certificate_verify(session))
    {
        return -RT_ERROR;
    }

    LOG_D("Certificate verified success...");

    return RT_EOK;
}

/**
 * @brief 向加密连接读取数据
 * 
 * @param session 入参，mbedtls 会话对象 MbedTLSSession
 * @param buf  入参，mbedtls 读取内容的缓冲区
 * @param len 入参，mbedtls 待读取内容长度
 * 
 * @return 0 成功  !0失败
 */
int mbedtls_client_read(MbedTLSSession *session, unsigned char *buf , size_t len)
{
    int ret = 0;

    if (session == RT_NULL || buf == RT_NULL)
    {
        return -RT_ERROR;
    } 

    // 从 SLL/TLS 读取数据，最多读取 'len' 字节长度数据字节
    ret = mbedtls_ssl_read(&session->ssl,           // SSL 上下文结构体对象
                           (unsigned char *)buf,    // 接收读取数据的缓冲区
                           len);                    // 要读取的数据长度

    // > 0                              : 读取到的数据长度
    // = 0                              : 读取到结束符
    // MBEDTLS_ERR_SSL_WANT_READ        : SSL 客户端需要读取调用
    // MBEDTLS_ERR_SSL_WANT_WRITE       : SSL 客户端需要写入调用
    // MBEDTLS_ERR_SSL_CLIENT_RECONNECT : SSL 客户端需要重连
    // other                            : 其它 SSL 指定的错误码
    if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        LOG_E("mbedtls_client_read data error, return -0x%x", -ret);
    }

    return ret;
}

/**
 * @brief 向加密连接写入数据
 * 
 * @param session 入参，mbedtls 会话对象 MbedTLSSession
 * @param buf  入参，mbedtls 待写入内容的缓冲区
 * @param len 入参，mbedtls 待写入内容长度
 * 
 * @return 0 成功  !0失败
 */
int mbedtls_client_write(MbedTLSSession *session, const unsigned char *buf , size_t len)
{
    int ret = 0;

    if (session == RT_NULL || buf == RT_NULL)
    {
        return -RT_ERROR;
    }

    // 向 SSL/TLS 写入数据，最多写入 'len' 字节长度数据。
    ret = mbedtls_ssl_write(&session->ssl, (unsigned char *)buf, len);

    // > 0                              : 实际写入的数据长度
    // = 0                              : 读取到结束符
    // MBEDTLS_ERR_SSL_WANT_READ        : SSL 客户端需要读取调用
    // MBEDTLS_ERR_SSL_WANT_WRITE       : SSL 客户端需要写入调用
    // MBEDTLS_ERR_SSL_CLIENT_RECONNECT : SSL 客户端需要重连
    // other                            : 其它 SSL 指定的错误码
    if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        LOG_E("mbedtls_client_write data error, return -0x%x", -ret);
    }

    return ret;
}
