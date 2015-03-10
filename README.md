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
       1. push_config (string)
       2. push_db (string)
       3. push_table (string)
       4. push_flag (integer)
       5. push_apns_cert (string)
       6. push_apns_key (string)
       7. push_apns_cafile (string)
       8. push_apns_server (string)
       9. push_apns_port (integer)
       10. push_apns_alert (string)
       11. push_apns_sound (string)
       12. push_apns_badge (integer)
       13. push_apns_rtimeout (integer)
       14. push_apns_feedback_server (string)
       15. push_apns_feedback_port (integer)
       16. push_apns_feedback_rtimeout (integer)
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

#### 1. push_config (string)

#### 2. push_db (string)
Defines database to store push related information
```
modparam("push", "push_db", DBURL)
```