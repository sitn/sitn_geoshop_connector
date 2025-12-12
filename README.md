# EXTRACT connector for geoshop

This connector is meant to connect [geoshop](https://github.com/camptocamp/geoshop-backend) in [EXTRACT](https://github.com/asit-asso/extract).

## How to use

Downlaod the JAR file from a released version and paste it into your installed Extract in `WEB-INF/classes/connectors`

## Dev environement

### Requirements

 * JDK 17
 * mvn 3.9+ (binaries in the PATH)

### Build

First install the plugin interface:

```powershell
cd plugin-interface
mvn clean install
```

```powershell
cd connectors/extract-connector-geoshop
```
