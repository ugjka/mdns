# Introduction

This package allows Go processes to publish multicast DNS style records onto their local network segment. For more information about mDNS, and it's closely related cousin, Zeroconf, please visit <http://www.multicastdns.org/>.

## Acknowledgements

Thanks to Brian Ketelsen and Miek Gieben for their feedback and suggestions. This package builds on Miek's fantastic godns library and would not have been possible without it.

## Installation

This package can be installed using:

`go get github.com/ugjka/mdns`

For development, this package is developed with John Asmuths excellent gb utility.

## Usage

Publishing mDNS records is simple

```go
import "github.com/ugjka/mdns"

func main(){
    zone, err := mdns.New()
    if err != nil {
            log.Fatal(err)
    }
    zone.Publish("yourhost.local 60 IN A 192.168.1.100")
}
```
