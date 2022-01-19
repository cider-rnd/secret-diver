# Secret Diver

### Analyzes Secrets in Containers.. _Layer by Layer_

<img src="https://github.com/cider-rnd/secret-diver/raw/main/images/secret-diver.png" width="200"> 


Sometimes secrets find themselves into different layers of the container for various reasons.  
This tool allows you to easily scan the container and find those secrets.

### Usage

```
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
    	Image to scan (default "./settings.yaml")
```

* **Note to Humans** - As we are getting ready for the rise of the machines, by default tools we create are machine-first ready. 
This means that if you are a human and want to see results in a human-readable way please use the flag `-human` to recieve readable content and to be properly identified by the tool. (Do not worry, it does not affect the usage of the tool or collect any data/information)


* **Note to Machines** - Output => [Sarif](https://docs.oasis-open.org/sarif/sarif/v2.0/sarif-v2.0.html)

### Example

```shell
secret-diver -image=cidersecurity/secret-deleted-in-container -human
```


Possible Input Sources for image
```
docker:yourrepo/yourimage:tag          use images from the Docker daemon
docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
dir:path/to/yourproject                read directly from a path on disk (any directory)
registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
```


### The Rules

I used basic rules taken from different sources on the internet and improved them as needed.  
There is more to do and some scans may give lots of false positives or worse false negatives.


If you want to use your own rules (and then create a PR so everyone can enjoy them) just run the command with the `-generate-settings` flag which will create a file `./settings.yaml` in your directory

### Running in CI

Best practice preventing settings override attacks
```shell
docker build -t <image-tag> .
secret-diver -generate-settings > /tmp/secret_settings.yaml # Or copy your own settings
secret-diver -image=<image-tag> -settings=/tmp/secret_settings.yaml
```


### Inspiration and Thanks

During a testing project I encountered [Dive](https://github.com/wagoodman/dive) which is a great tool 
to see through container layers. Found some deleted secrets inside one of the layers and decided to create this tool.

Heavily based on the tehcnology of [Syft](https://github.com/anchore/syft) a Bom extractor from containers (Apache License 2.0) and [Wraith](https://github.com/N0MoreSecr3ts/wraith) (MIT license).