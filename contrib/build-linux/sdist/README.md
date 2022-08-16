# Source tarballs

✓ _This file should be reproducible, meaning you should be able to generate
   distributables that match the official releases._

This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another
similar system. The docker commands should be executed in the project's root
folder.

We distribute two tarballs, a "normal" one (the default, recommended for users),
and a strictly source-only one (for Linux distro packagers).
The normal tarball, in addition to including everything from
the source-only one, also includes:
- compiled (`.mo`) locale files (in addition to source `.po` locale files)
- compiled (`_pb2.py`) protobuf files (in addition to source `.proto` files)
- the `packages/` folder containing source-only pure-python runtime dependencies


## Build steps

1. Install Docker

    ```
    $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    $ sudo apt-get update
    $ sudo apt-get install -y docker-ce
    ```

2. Build image

    ```
    $ sudo docker build -t electrum-nmc-sdist-builder-img contrib/build-linux/sdist
    ```

3. Build tarballs

    It's recommended to build from a fresh clone
    (but you can skip this if reproducibility is not necessary).

    ```
    $ FRESH_CLONE=contrib/build-linux/sdist/fresh_clone && \
        sudo rm -rf $FRESH_CLONE && \
        umask 0022 && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone https://github.com/namecoin/electrum-nmc.git && \
        cd electrum-nmc
    ```

    And then build from this directory (set envvar `OMIT_UNCLEAN_FILES=1` to build the "source-only" tarball):
    ```
    $ git checkout $REV
    $ sudo docker run -it \
        --name electrum-nmc-sdist-builder-cont \
        -v $PWD:/opt/electrum-nmc \
        --rm \
        --workdir /opt/electrum-nmc/contrib/build-linux/sdist \
        --env OMIT_UNCLEAN_FILES \
        electrum-nmc-sdist-builder-img \
        ./build.sh
    ```
4. The generated distributables are in `./dist`.
