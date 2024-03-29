# SecretDiver
Analyzes Secrets in Containers.. _Layer by Layer_

<img src="https://github.com/cider-rnd/secret-diver/raw/main/images/secret-diver.png" width="200"> 


Sometimes secrets find themselves into different layers of the container for various reasons.  
This tool allows you to easily scan the container and find those secrets.


## Usage

* **Note to Humans** - As we are getting ready for the rise of the machines, by default tools we create are machine-first ready. 
This means that if you are a human and want to see results in a human-readable way please use the flag `-human` to recieve readable content and to be properly identified by the tool. (Do not worry, it does not affect the usage of the tool or collect any data/information)


* **Note to Machines** - Output => [Sarif](https://docs.oasis-open.org/sarif/sarif/v2.0/sarif-v2.0.html)


```text
Usage of ./secret-diver:
  -generate-settings
    	generates default settings.yaml in current directory
  -human
    	Allows humans to use the tool
  -image string
    	Image to scan
  -output string
    	Output file
  -settings string
    	Settings for the scan (default "./settings.yaml")
```

## Local install

```bash
$ go install -v github.com/cider-rnd/secret-diver@v0.0.1
$ secret-diver -image=cidersecurity/secret-deleted-in-container -human
```


## Source image scanning options:
```
docker:yourrepo/yourimage:tag          use images from the Docker daemon
docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
dir:path/to/yourproject                read directly from a path on disk (any directory)
registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
```


### Running in CI

Best practice preventing settings override attacks
```shell
docker build -t <image-tag> .
secret-diver -generate-settings > /tmp/secret_settings.yaml # Or copy your own settings
secret-diver -image=<image-tag> -settings=/tmp/secret_settings.yaml
```

### Running with Docker
If you'd like to run the scanner from another container, you can choose one of the below options;

In all cases, it is cardinal to run the container and mount the `docker.sock`, something like: `-v /var/run/docker.sock:/var/run/docker.sock` will work great.
Failing to do so will result in a crash as we use docker for fetching images.

#### **CLI**
```bash
$ docker run \
 -v /var/run/docker.sock:/var/run/docker.sock \
 cidersecurity/secret-diver:latest -image=node:16 -human
```

#### **clone and build Dockerfile**
You can clone the repo and [use our Dockerfile ](https://github.com/cider-rnd/secret-diver/blob/main/Dockerfile)


#### **slim recipe**
```dockerfile
FROM docker:latest

COPY --from=golang:1.19-alpine /usr/local/go/ /usr/local/go/
 
ENV PATH="/usr/local/go/bin:${PATH}:/root/go/bin"

RUN go install -v github.com/cider-rnd/secret-diver@v0.0.1

ENTRYPOINT [ "secret-diver" ]
```


## The Rules

We used basic rules taken from different sources on the internet and improved them as needed.
There is more to do and some scans may give lots of false-positives or worse, false-negatives 😱.


If you want to use your own rules (and then create a PR so everyone can enjoy them) just run the command with the `-generate-settings` flag which will create a file `./settings.yaml` in your directory


## Inspiration and Thanks

During a testing project I encountered [Dive](https://github.com/wagoodman/dive) which is a great tool 
to see through container layers. Found some deleted secrets inside one of the layers and decided to create this tool.

Heavily based on the tehcnology of [Syft](https://github.com/anchore/syft) a Bom extractor from containers (Apache License 2.0) and [Wraith](https://github.com/N0MoreSecr3ts/wraith) (MIT license).