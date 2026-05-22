# WireSentinel Client

Agente Linux em C responsável por capturar metadados de tráfego de rede via raw socket, normalizar os pacotes em JSON e enviar batches autenticados para o WireSentinel Server.

O cliente não armazena pacotes localmente em banco. Ele mantém apenas arquivos locais de configuração e identificação do agente:

- `.security`: segredo compartilhado e endereço do servidor.
- `.uuid`: UUID gerado pelo servidor para identificar esta instalação/agente.

---

# Índice

- [Visão geral do fluxo](#visão-geral-do-fluxo)
- [Requisitos](#requisitos)
  - [Sistema operacional](#sistema-operacional)
  - [Dependências de build](#dependências-de-build)
- [Build](#build)
- [Configuração local](#configuração-local)
- [Inicialização do agente](#inicialização-do-agente)
- [Autenticação entre cliente e servidor](#autenticação-entre-cliente-e-servidor)
- [Registro do agente](#registro-do-agente)
- [Validação de UUID existente](#validação-de-uuid-existente)
- [Captura de pacotes](#captura-de-pacotes)
- [Pipeline interno](#pipeline-interno)
  - [`Buffer_List`](#buffer_list)
  - [`PacketList`](#packetlist)
- [Protocolos parseados](#protocolos-parseados)
  - [Camada Ethernet](#camada-ethernet)
  - [IPv4](#ipv4)
  - [IPv6](#ipv6)
  - [TCP](#tcp)
  - [UDP](#udp)
  - [Aplicação](#aplicação)
- [Payload JSON enviado ao servidor](#payload-json-enviado-ao-servidor)
- [Campos enviados](#campos-enviados)
- [Respostas esperadas do servidor](#respostas-esperadas-do-servidor)
  - [`/api/register`](#apiregister)
  - [`/api/client_auth`](#apiclient_auth)
  - [`/api/ingest`](#apiingest)
- [Execução como serviço systemd](#execução-como-serviço-systemd)
- [Checklist operacional](#checklist-operacional)
- [Relação com o frontend](#relação-com-o-frontend)

## Visão geral do fluxo

```text
Interface de rede Linux
        │
        ▼
Raw socket AF_PACKET / ETH_P_ALL
        │
        ▼
Buffer interno de frames brutos
        │
        ▼
Parser Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP / ICMP
        │
        ▼
Lista de metadados de pacotes
        │
        ▼
Batch JSON
        │
        ▼
HTTP POST /api/ingest com HMAC SHA-256
        │
        ▼
WireSentinel Server / PostgreSQL / Frontend
```

O agente captura frames Ethernet brutos, extrai metadados de camada 2, camada 3 e camada 4, identifica protocolos conhecidos por porta e envia o resultado ao backend.

---

## Requisitos

### Sistema operacional

- Linux.
- Permissão para criar raw socket `AF_PACKET`.

Execução comum:

```bash
sudo ./WireSentinel_Client
```

Alternativa com capability:

```bash
sudo setcap cap_net_raw+ep ./WireSentinel_Client
./WireSentinel_Client
```

### Dependências de build

Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev
```

Arch Linux:

```bash
sudo pacman -S --needed base-devel cmake openssl
```

---

## Build

```bash
cmake -S . -B build
cmake --build build
```

Binário gerado:

```bash
./build/WireSentinel_Client
```

Execução:

```bash
sudo ./build/WireSentinel_Client
```

---

## Configuração local

Na primeira execução, o agente solicita:

```text
Digite a Chave Compartilhada
Digite a URL
Digite a Porta
```

Esses dados são gravados em `.security` no diretório de execução.

Formato do arquivo:

```env
SHRD_SCRT=minha-chave-compartilhada
URL=192.168.0.146
PORT=8080
```

Campos:

| Campo | Descrição |
|---|---|
| `SHRD_SCRT` | Segredo compartilhado usado para gerar HMAC SHA-256. Deve ser igual ao `WIRESENTINEL_SECRET` do servidor. |
| `URL` | Host/IP onde o servidor está disponível. Exemplo: `192.168.0.146`. |
| `PORT` | Porta HTTP do servidor. Exemplo: `8080`. |

Depois que o agente se registra no servidor, ele cria `.uuid`:

```env
UUID=550e8400-e29b-41d4-a716-446655440000
```

Esse UUID é a identidade do agente no backend. É o valor que o usuário cola no frontend para vincular a máquina à própria conta.

---

## Inicialização do agente

Ao iniciar, o cliente segue esta ordem:

1. Carrega ou cria `.security`.
2. Abre conexão TCP com o servidor configurado.
3. Verifica se `.uuid` existe.
4. Se `.uuid` existir, autentica o agente em `GET /api/client_auth`.
5. Se `.uuid` não existir, ou se a autenticação falhar, registra a máquina em `GET /api/register`.
6. Salva o UUID retornado em `.uuid`.
7. Inicia captura de pacotes com raw socket.
8. Processa frames em uma thread dedicada.
9. Envia batches JSON ao servidor em `POST /api/ingest`.

---

## Autenticação entre cliente e servidor

O agente não usa JWT. JWT é usado apenas por usuários do frontend.

A comunicação agente-servidor usa:

- segredo compartilhado `SHRD_SCRT` / `WIRESENTINEL_SECRET`;
- HMAC SHA-256;
- timestamp por requisição;
- UUID do agente após registro.

Todos os HMACs são enviados em hexadecimal lowercase no header:

```http
X-WireSentinel-Credential: <hmac_hex>
```

O servidor valida se o timestamp está dentro da janela operacional de 3 minutos e se o HMAC bate com a string assinada.

---

## Registro do agente

Endpoint chamado quando o agente ainda não possui UUID válido.

```http
GET /api/register HTTP/1.1
Host: <host>:<port>
X-WireSentinel-Timestamp: <timestamp>
X-WireSentinel-Credential: <hmac_hex>
User-Agent: WireSentinel-Agent/1.0
```

String assinada para o HMAC:

```text
{
  X-WireSentinel-Timestamp: <timestamp>,
  User-Agent: WireSentinel-Agent/1.0
}
```

Representação visual:

```text
{
  X-WireSentinel-Timestamp: 2026-05-20T09:31:23,
  User-Agent: WireSentinel-Agent/1.0
}
```

Resposta esperada:

```http
HTTP/1.1 200 OK

550e8400-e29b-41d4-a716-446655440000
```

O body é texto puro contendo o UUID.

---

## Validação de UUID existente

Endpoint usado quando `.uuid` já existe localmente.

```http
GET /api/client_auth HTTP/1.1
Host: <host>:<port>
X-WireSentinel-Timestamp: <timestamp>
X-WireSentinel-Credential: <hmac_hex>
X-WireSentinel-UUID: <uuid>
User-Agent: WireSentinel-Agent/1.0
```

String assinada:

```text
{
  X-WireSentinel-Timestamp: <timestamp>,
  User-Agent: WireSentinel-Agent/1.0
}
```

Resposta esperada:

```http
HTTP/1.1 200 OK
```

Se a validação não retornar `200`, o agente solicita novo registro em `/api/register` e atualiza `.uuid`.

---

## Captura de pacotes

O agente cria um raw socket:

```c
socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
```

Esse socket recebe frames de camada 2 diretamente da interface de rede.

A captura principal usa `recvfrom()` em loop contínuo. Cada frame recebido é copiado para uma fila interna de buffers brutos. Uma thread de processamento consome essa fila, parseia o frame e transforma em `FullInternetPacket`.

---

## Pipeline interno

O cliente usa duas estruturas principais:

### `Buffer_List`

Armazena frames brutos recebidos pelo raw socket.

Campos:

```c
typedef struct node {
    unsigned char content[65535];
    long int recvlen;
    struct node *next;
} Buffer_List;
```

### `PacketList`

Armazena pacotes já parseados e prontos para serialização JSON.

```c
typedef struct PacketList {
    FullInternetPacket *packet;
    struct PacketList *next;
} PacketList;
```

O agente sinaliza envio de payload quando:

- acumula atividade suficiente de pacotes processados; ou
- passa o intervalo de flush configurado no loop principal.

No código atual, o loop principal sinaliza a thread de payload quando chega a aproximadamente 2000 pacotes processados ou quando passa cerca de 4 segundos desde o último flush.

---

## Protocolos parseados

### Camada Ethernet

O parser extrai:

- MAC de origem;
- MAC de destino;
- EtherType;
- presença de VLAN.

EtherTypes tratados:

| EtherType | Nome |
|---:|---|
| `0x0800` | IPv4 |
| `0x86DD` | IPv6 |
| `0x0806` | ARP |
| `0x8035` | RARP |
| `0x8100` | VLAN 802.1Q |
| `0x88A8` | QinQ / provider bridging |
| `0x8847` | MPLS Unicast |
| `0x8848` | MPLS Multicast |
| `0x8863` | PPPoE Discovery |
| `0x8864` | PPPoE Session |

### IPv4

Campos extraídos:

- IP origem;
- IP destino;
- TTL;
- tamanho do header IPv4;
- protocolo de transporte.

Protocolos tratados:

| Número | Nome |
|---:|---|
| `1` | ICMP |
| `5` | STREAM |
| `6` | TCP |
| `17` | UDP |

### IPv6

Campos extraídos:

- IP origem;
- IP destino;
- Hop Limit;
- próximo header;
- extension headers conhecidos.

Extension headers tratados:

| Número | Nome |
|---:|---|
| `0` | Hop-by-Hop Options |
| `43` | Routing Header |
| `44` | Fragment Header |
| `60` | Destination Options |

Protocolos finais tratados:

| Número | Nome |
|---:|---|
| `1` | ICMP |
| `5` | STREAM |
| `6` | TCP |
| `17` | UDP |
| `58` | ICMPv6 |

### TCP

Campos extraídos:

- porta origem;
- porta destino;
- sequence number;
- acknowledgment number;
- flags TCP.

Flags enviadas:

- `tcpAck`
- `tcpFin`
- `tcpSyn`
- `tcpRst`
- `tcpPsh`
- `tcpUrg`
- `tcpCwr`
- `tcpEce`

### UDP

Campos extraídos:

- porta origem;
- porta destino.

### Aplicação

O cliente possui uma tabela local de serviços por porta TCP/UDP em `include/services_table.h`.

Exemplos:

| Porta | Nome |
|---:|---|
| `22` | `ssh` |
| `53` | `domain` |
| `80` | `http` |
| `443` | `https` |

O campo gerado é:

```json
"protocolo_aplicacao": "https"
```

Quando a porta não está mapeada:

```json
"protocolo_aplicacao": "Unknown/None"
```

---

## Payload JSON enviado ao servidor

Endpoint:

```http
POST /api/ingest HTTP/1.1
Host: <host>:<port>
Content-Type: application/json
Content-Length: <tamanho-do-body>
X-WireSentinel-Timestamp: <timestamp>
X-WireSentinel-Credential: <hmac_hex>
X-WireSentinel-UUID: <uuid>
User-Agent: WireSentinel-Agent/1.0
```

String assinada para o HMAC:

```text
{
  X-WireSentinel-Timestamp: <timestamp>,
  Length: <content_length>
}
```

Body:

```json
{
  "packets": [
    {
      "timestamp": "2026-05-20T09:31:23",
      "macAdressOrigem": "aa:bb:cc:dd:ee:ff",
      "macAdressDestino": "11:22:33:44:55:66",
      "protocoloIp": "IPv4",
      "ipOrigem": "192.168.0.10",
      "ipDestino": "8.8.8.8",
      "tempoDeVida": 64,
      "tamanhoTotalHeader": 54,
      "tamanhoTotalPacote": 1500,
      "portaOrigem": 51544,
      "portaDestino": 443,
      "tcpSeq": 123456789,
      "tcpAckSeq": 987654321,
      "tcpAck": true,
      "tcpFin": false,
      "tcpSyn": true,
      "tcpRst": false,
      "tcpPsh": false,
      "tcpUrg": false,
      "tcpCwr": false,
      "tcpEce": false,
      "isVlan": false,
      "protocolo_transporte": "TCP",
      "protocolo_aplicacao": "https"
    }
  ]
}
```

Observação importante para integração: o UUID não vai dentro de cada pacote no body. Ele é enviado no header `X-WireSentinel-UUID`. O servidor injeta esse UUID em cada entidade antes de persistir.

---

## Campos enviados

| Campo JSON | Origem | Descrição |
|---|---|---|
| `timestamp` | Cliente | Momento em que o pacote foi parseado. |
| `macAdressOrigem` | Ethernet | MAC de origem. |
| `macAdressDestino` | Ethernet | MAC de destino. |
| `protocoloIp` | EtherType | IPv4, IPv6, ARP, RARP, MPLS, PPPoE ou Unknown. |
| `ipOrigem` | IPv4/IPv6 | IP de origem ou `Null`. |
| `ipDestino` | IPv4/IPv6 | IP de destino ou `Null`. |
| `tempoDeVida` | IPv4 TTL / IPv6 Hop Limit | TTL ou Hop Limit. |
| `tamanhoTotalHeader` | Parser | Soma dos headers parseados até transporte. |
| `tamanhoTotalPacote` | Captura | Tamanho total recebido pelo raw socket. |
| `portaOrigem` | TCP/UDP | Porta de origem ou `0`. |
| `portaDestino` | TCP/UDP | Porta de destino ou `0`. |
| `tcpSeq` | TCP | Sequence number ou `0`. |
| `tcpAckSeq` | TCP | Acknowledgment number ou `0`. |
| `tcpAck` | TCP | Flag ACK. |
| `tcpFin` | TCP | Flag FIN. |
| `tcpSyn` | TCP | Flag SYN. |
| `tcpRst` | TCP | Flag RST. |
| `tcpPsh` | TCP | Flag PSH. |
| `tcpUrg` | TCP | Flag URG. |
| `tcpCwr` | TCP | Flag CWR. |
| `tcpEce` | TCP | Flag ECE. |
| `isVlan` | Ethernet | Indica pacote VLAN 802.1Q. |
| `protocolo_transporte` | IP next protocol | TCP, UDP, ICMP, ICMPv6, STREAM ou Unknown/None. |
| `protocolo_aplicacao` | Porta TCP/UDP | Serviço conhecido ou Unknown/None. |

---

## Respostas esperadas do servidor

### `/api/register`

| Status | Ação do cliente |
|---:|---|
| `200` | Extrai UUID do body e grava `.uuid`. |
| `400` | Encerra com erro de registro inválido. |
| `401` | Encerra com erro de credencial/HMAC. |

### `/api/client_auth`

| Status | Ação do cliente |
|---:|---|
| `200` | Usa UUID atual. |
| diferente de `200` | Solicita novo registro em `/api/register`. |

### `/api/ingest`

| Status | Ação do cliente |
|---:|---|
| `200` | Considera batch enviado. |
| diferente de `200` | Revalida/registra UUID e retoma envio. |

---

## Execução como serviço systemd

Exemplo de unidade:

```ini
[Unit]
Description=WireSentinel Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/wiresentinel-client
ExecStart=/opt/wiresentinel-client/WireSentinel_Client
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

Instalação:

```bash
sudo mkdir -p /opt/wiresentinel-client
sudo cp build/WireSentinel_Client /opt/wiresentinel-client/
sudo cp .security /opt/wiresentinel-client/ # se já existir
sudo nano /etc/systemd/system/wiresentinel-client.service
sudo systemctl daemon-reload
sudo systemctl enable --now wiresentinel-client
```

Logs:

```bash
journalctl -u wiresentinel-client -f
```

---

## Checklist operacional

1. O servidor está acessível pelo host/porta configurados em `.security`.
2. `SHRD_SCRT` é igual ao `WIRESENTINEL_SECRET` do servidor.
3. O relógio do host está sincronizado, pois o servidor valida timestamp.
4. O processo tem permissão para raw socket.
5. O frontend mostra o sistema depois que o UUID do `.uuid` é vinculado à conta do usuário.

---

## Relação com o frontend

O cliente C não autentica usuário e não conversa com o frontend.

Fluxo correto:

1. Cliente C registra a máquina no servidor e gera `.uuid`.
2. Usuário acessa o frontend.
3. Usuário faz login.
4. Usuário cola o UUID do agente na tela de vínculo.
5. Frontend passa a listar o sistema e seus pacotes.
