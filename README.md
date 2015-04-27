# push
## Kamailio Push notification module

   Volodymyr Tarasenko
   Copyright © 2014 Volodymyr Tarasenko

#### Table of Contents
  Admin Guide
  1. Overview
  2. Dependencies
    1. Kamailio Modules
    2. External Libraries or Applications
  3. Parameters
    1. push_db (string)
    2. push_table (string)
    3. push_flag (integer)
    4. push_apns_cert (string)
    5. push_apns_key (string)
    6. push_apns_cafile (string)
    7. push_apns_server (string)
    8. push_apns_port (integer)
    9. push_apns_alert (string)
    10. push_apns_sound (string)
    11. push_apns_badge (integer)
    12. push_apns_rtimeout (integer)
    13. push_apns_feedback_server (string)
    14. push_apns_feedback_port (integer)
    15. push_apns_feedback_rtimeout (integer)
  4. Functions
    1. push_request
    2. push_register
    3. push_message
  5. Installation

## Admin Guide

### 1. Overview
This is a module which provides Push notification service for Kamailio. It
implements the APNS interface (currently). In nearest plans extend it to 
support Android push notifications (GCM)


### 2. Dependencies
  1. Kamailio Modules
  2. External Libraries or Applications

#### 1. Kamailio Modules
  * No dependencies on other Kamailio modules.

#### 2. External Libraries or Applications
The following libraries or applications must be installed before
running Kamailio with this module loaded:
  * openssl

### 3. Parameters

#### 1. push_db (string)
Defines database to store push related information
```
modparam("push", "push_db", DBURL)
```

#### 2. push_table (string)
Defines table to store push related information
```
modparam("push", "push_table", "push_apns")
```

#### 3. push_flag (integer)
Set the flag for the push, next values are possible:
  - 0 - establish connection to push server immediately after start
  - 1 - establish connection upon request
  - 2 - do not reconnect in case of error
```
modparam("push", "push_flag", 0)
```

#### 4. push_apns_cert (string)
Defines the path to apns cert file
```
modparam("push", "push_apns_cert", "/etc/kamailio/apns/cert.pem")
```

#### 5. push_apns_key (string)
Defines the path to apns key file
```
modparam("push", "push_apns_key", "/etc/kamailio/apns/key.pem")
```

#### 6. push_apns_cafile (string)
Defines the path to apns CA cert if any, it should be defined if test server is used
```
modparam("push", "push_apns_cafile", "/etc/kamailio/apns/entrust_2048_ca.pem")
```

#### 7. push_apns_server (string)
Defines apns server to use
```
modparam("push", "push_apns_server", "gateway.sandbox.push.apple.com")
```

#### 9. push_apns_port (integer)
Defines apns server port
```
modparam("push", "push_apns_port", 2195)
```

#### 9. push_apns_alert (string)
Defines default apns alert string

#### 10. push_apns_sound (string)
Defines default apns sound file to play on device

#### 11. push_apns_badge (integer)
Defines default apns badge number

#### 12. push_apns_rtimeout (integer)
Defines read timeout for apns communication, defined in microseconds
```
modparam("push", "push_apns_rtimeout", 10000)
```

#### 13. push_apns_feedback_server (string)
Defines apns feedback server to use, if any

#### 14. push_apns_feedback_port (integer)
Defines apns feedback server port

#### 15. push_apns_feedback_rtimeout (integer)
Defines read timeout for apns feedback comunnication, defined in microseconds
