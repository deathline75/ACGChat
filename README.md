ACGChat
---
We use Gradle as our dependency manager and InteliJ as our IDE.

### Authors
- [Kelvin Neo](https://github.com/deathline75)
- [Darren Ang](https://github.com/txsouth)
- [Chen Qiurong](https://github.com/pc84560895)
- [Jonathan Lee](https://github.com/wutdequack)

### Dependencies 
- Apache Commons CLI
- Bouncy Castle
- InteliJ GUI Designer

### Building the Project
To compile everything at once:
```
gradle
```
To compile the client (command line version), use:
```
gradle clientJar
```
To compile the client (GUI version), use:
```
gradle clientGUIJar
```
To compile the server (command line version), use:
```
gradle serverJar
```
To compile the server (GUI version), use:
```
gradle serverGUIJar
```

### Prerequisites before running any program
For the server, you will need to have a keystore with a public key signed by a Root CA (could be self-signed). 
By default, the application will check for `ACGChatKeystore.pfx`.
The format that is currently supported is PCKS#12.

For the client, you will need to provide the root CA's certificate. 
By default, the application will check for `ACGChatCA.cert`.
The format that is currently supported is X.509 Certificate.

### Client CLI Options
```
-a      --server-address:       IP address or hostname of server
-p      --server-port:          Port number of server
-l      --login:                Set as login mode
-r      --register:             Set as register mode
-u      --username:             Username
-up     --password:             Password
-c      --certificate:          Path to certificate of Root CA (X.509)
```

### Server CLI Options
```
-p      --port:                 Port number to bind to
-c      --credential:           Path to credential file
-k      --keystore:             Path to keystore file
-kp     --keystore-password:    Keystore's password
-a      --alias:                Alias of the server key in keystore
-ap     --alias-password:       Associated alias password
```

### GUI Version
For server, all the settings can be set based on the tabs in the interface.

For client, the certificate setting cannot be set currently.