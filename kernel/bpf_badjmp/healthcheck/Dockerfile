# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ubuntu:hirsute as exploit-build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y build-essential llvm linux-tools-generic libbpf-dev

COPY exploit /exploit

RUN make -C /exploit BPFTOOL=$(echo /usr/lib/linux-tools/*/bpftool)

FROM gcr.io/kctf-docker/healthcheck@sha256:18fe7058d40100b7eb2eca0a274fc2f41403d44706ae969bcef01400b3bfde64

COPY healthcheck_loop.sh healthcheck.py healthz_webserver.py /home/user/
COPY --from=exploit-build /exploit/bpf /home/user/exploit

CMD kctf_drop_privs /home/user/healthcheck_loop.sh & /home/user/healthz_webserver.py
