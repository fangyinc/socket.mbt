# A socket binding for MoonBit

## Usage

To use a package from this repository, add module `fangyinc/socket` to 
dependencies by command

```
moon add fangyinc/socket
``` 

And import socket in your `moon.pkg.json` file. for example:

```json
{
  "import": [
    "fangyinc/socket/lib"
  ]
}
```

## Use Example

You can find the tcp echo server example in [src/examples/tcp_server](src/examples/tcp_server) and the tcp client example in [src/examples/tcp_client](src/examples/tcp_client).