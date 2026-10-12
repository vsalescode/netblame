# netblame

[English version](README.en.md)

**Descubra _onde_ a sua conexão cai: no seu PC, no roteador, no provedor ou na rota até o servidor.**

Você está no meio de uma partida, de uma chamada ou de uma sessão remota e aparece *"conexão perdida"*
de novo. É o cabo? O roteador? O provedor? Os servidores do jogo? Normalmente não dá para saber, e
cada um culpa o outro. O netblame observa vários pontos do caminho de rede ao mesmo tempo e compara
quais falham juntos. Esse padrão mostra onde está o defeito.

![Relatório do netblame para o cenário sintético "isp"](docs/report-demo-pt.png)

*Relatório gerado por `netblame demo --scenario isp` (dados sintéticos). Relatórios HTML completos de
cada cenário: [isp](docs/demo-isp.html) · [local](docs/demo-local.html) · [route](docs/demo-route.html) ·
[udp](docs/demo-udp.html) · [pc](docs/demo-pc.html) · [healthy](docs/demo-healthy.html). Baixe e abra
no navegador.*

- Feito para Windows, **sem administrador** e **só com a biblioteca padrão** (o `psutil` é opcional)
- Funciona com o Windows em qualquer idioma. Os parsers nunca dependem de palavras traduzidas.
- Um relatório HTML único e autocontido: abre sem internet e pode ser anexado num chamado para o provedor
- **Bilíngue: português e inglês.** O relatório tem um botão EN | PT, com as duas línguas no mesmo
  arquivo. Quem recebe o relatório lê no próprio idioma.

## Como funciona

A cada ciclo (padrão: a cada segundo), tudo isto é sondado **em paralelo**:

| Sonda | Alvo padrão | Responde |
|---|---|---|
| Ping ICMP | o seu **gateway** (roteador, detectado automaticamente) | A minha rede local está ok? |
| Ping ICMP | `1.1.1.1` e `8.8.8.8` | A internet está acessível? |
| DNS via **UDP** | os **mesmos** `1.1.1.1` e `8.8.8.8` | A rede trata UDP (o protocolo dos jogos) pior que ping? |
| Conexão TCP | o **app** que importa para você (`--preset battlenet`, `--target jogo=tcp://host:porta`) | Consigo chegar *nesse serviço*? |
| Consulta DNS | o servidor DNS configurado no sistema | A resolução de nomes funciona? |
| Ping por salto | cada salto da rota até a internet e até o app | Em que ponto da rota a perda começa? |
| Contadores UDP | o Windows (`GetUdpStatisticsEx`) | O próprio PC descartou pacotes UDP que chegaram? |
| psutil | CPU, RAM, tráfego, velocidade e erros da placa de rede | O problema é o meu PC? |

Depois, o raciocínio é por eliminação:

```
                     quem falhou no mesmo ciclo?
                                  │
       ┌──────────────────────────┼──────────────────────────────┐
       │                          │                              │
 roteador E todos os       roteador OK, TODOS os         só o alvo do app
 alvos externos            alvos externos fora           está ruim
       │                          │                              │
       ▼                          ▼                              ▼
  problema LOCAL            problema no MODEM/PROVEDOR     problema de ROTA ou SERVIDOR
  cabo · placa · roteador   (apagão "upstream")            (fora da sua casa)
       │                          │                              │
       └────────────┬─────────────┴──────────────┬───────────────┘
                    │                            │
     salto a salto: a perda começa no salto N  ...e vai até o fim  → o salto N é o culpado
                                               ...e some depois    → limite de ICMP, ignorar

 Checagens cruzadas:  perdas ⇔ CPU ≥ 90% / RAM ≥ 95%        → o PC, não a rede
                      UDP perde, ping ao mesmo IP não        → roteador/provedor tratando UDP mal
                      Windows descarta UDP recebido          → PC não deu conta (CPU, antivírus, VPN)
                      DNS falha, ping por IP funciona        → servidor DNS
                      Ethernet a 100 Mbps em vez de 1000     → cabo ruim
                      contadores de erro da placa sobem      → cabo ou driver
                      p95 > 4× a mediana ou jitter > 30 ms   → bufferbloat / congestionamento
```

Algumas decisões que valem explicação:

- **Por que o `ping` do sistema e não sockets crus?** ICMP cru exige administrador no Windows, e
  ninguém quer rodar uma ferramenta de diagnóstico como admin. O `ping.exe` não pede privilégio. A
  saída dele é traduzida (`tempo=12ms` em pt-BR), então o parser só confia na estrutura: uma linha de
  resposta precisa ter `TTL=` e um trecho `[=<]\s*\d+\s*ms`. Isso também descarta corretamente o
  *"Host de destino inacessível"*, que o Windows imprime como "resposta" e com código de saída 0.
- **Por que UDP para os mesmos servidores do ping?** Jogos usam UDP, e alguns roteadores (SIP ALG,
  proteção contra flood) e provedores tratam UDP de outro jeito. Uma consulta DNS para o `1.1.1.1` é
  UDP de verdade para o **mesmo destino** do ping. Se só o UDP perde, o problema é o tratamento do
  protocolo, e não a rota.
- **Por que ignorar parte da perda nos saltos?** Roteadores encaminham tráfego em hardware, mas
  respondem a ping com a CPU que sobra, e quase todos limitam essas respostas. Um salto com 40% de
  perda cujos saltos seguintes têm 0% está ok. Só é real a perda que começa num salto *e continua até
  o destino*.
- **Por que os saltos são pingados durante toda a captura?** Quedas são intermitentes. Um traceroute
  rodado depois que o problema passou mostra uma rota limpa. O netblame traça a rota uma vez no
  início e pinga cada salto durante toda a captura, então as estatísticas por salto cobrem os mesmos
  minutos dos apagões.
- **Por que uma consulta DNS crua?** O `getaddrinfo` é respondido pelo cache DNS do Windows em ~0 ms
  e esconderia um resolvedor morto. O netblame monta a consulta com `struct` e manda direto ao
  servidor configurado, que é lido do registro (e não depende do idioma).
- **Por que o gateway falhando sozinho não é apagão?** Muitos roteadores despriorizam pings dirigidos
  a eles mesmos, mas encaminham o tráfego normalmente. Um apagão "local" exige que o roteador **e**
  todos os alvos externos falhem juntos.

## Instalação

Requer Python 3.10+.

```powershell
git clone https://github.com/vsalescode/netblame.git
cd netblame
pip install -e .            # só biblioteca padrão
pip install -e .[system]    # + psutil: CPU/RAM, tráfego, velocidade e erros da placa (recomendado)
```

Ou rode sem instalar: `python -m netblame ...`

## Uso

```powershell
# Captura de 10 minutos (padrão). Jogue ou trabalhe normalmente enquanto ela roda.
netblame run --preset battlenet --process Overwatch.exe --open

# Qualquer serviço: rótulo=tcp://host:porta para TCP, rótulo=host para ICMP. Pode repetir.
netblame run --minutes 30 --target jogo=tcp://meu.servidor.com:443 --target nas=192.168.0.10

# Gera o relatório de novo a partir de uma sessão salva (por exemplo, depois de atualizar o netblame)
netblame report netblame-session-20261011-213000.json --open

# Sessões sintéticas e reprodutíveis: isp | local | route | udp | pc | healthy
netblame demo --scenario udp --open
```

Aperte **Ctrl+C** a qualquer momento. A captura para de forma limpa e o relatório é gerado mesmo assim.

Idioma: `--lang pt|en` define a saída do terminal e o idioma inicial do relatório. O padrão segue o
idioma do sistema, e a variável de ambiente `NETBLAME_LANG` também pode definir.

Outras opções úteis:
- `--interval`: segundos entre ciclos.
- `--hop-every N`: pinga os saltos a cada N ciclos. O padrão é 2, porque abrir muitos `ping.exe` por
  segundo custa alguns % de CPU.
- `--dns-server`, `--no-trace`, `--no-dns`, `--no-udp`.
- Presets: `battlenet`, `steam`, `riot`, `epic`.

A saída é uma sessão `.json` (com as amostras brutas, para refazer a análise depois) e um relatório
`.html` único.

## O relatório

Feito para ser entendido por quem não é da área:

- **Mapa do caminho** na capa, como um mapa de metrô: `Seu PC → Rede de casa → Provedor → Internet →
  Servidor`. Cada estação fica verde, amarela ou vermelha, a linha aparece cortada onde está a falha e
  um selo marca "o problema está aqui". A manchete diz o resultado em português claro, por exemplo
  *"O problema está no seu provedor"*.
- **Em 30 segundos**: o resumo, um placar das 5 paradas e uma lista numerada do que fazer agora
- **Quando o jogo caiu**: com `--process`, o netblame percebe quando a CPU do jogo despenca (partida
  terminou ou caiu), mostra o horário real e diz como estava cada ponto da rede nos 5 segundos
  anteriores. O momento também fica marcado nos gráficos da linha do tempo.
- **Medidas principais** em réguas, como num exame de laboratório: perda, latência, jitter e tempo
  fora do ar, cada uma com o seu valor, a faixa bom/atenção/ruim e um "o que é isso?"
- **O caminho, parada por parada**: o que cada parada inclui, o que foi encontrado nela e o que fazer
- **Linha do tempo** com um bloco "como ler" em cada gráfico:
  - latência por alvo, com a linha interrompida nas perdas e os apagões sombreados;
  - faixa de perdas, uma linha por alvo;
  - carga do PC (CPU/RAM);
  - UDP vs ICMP.
  Passe o mouse (ou dê foco e use ←/→) para ver o crosshair com os valores.
- **Detalhes técnicos** recolhíveis, para o suporte da operadora: salto a salto (com o culpado
  destacado), estatísticas por alvo, apagões e placas de rede. Ao imprimir, tudo abre sozinho.
- **Glossário** com as palavras do relatório (latência, perda, jitter, salto, DNS, UDP...)
- **Botão EN | PT**. O navegador lembra a escolha, e o português usa vírgula decimal.
- Claro/escuro via `prefers-color-scheme`, paleta Okabe-Ito segura para daltonismo nos gráficos,
  status sempre com ícone e texto (nunca só cor), e layout responsivo: no celular, o mapa vira uma
  linha vertical.

## Limitações (leia)

- **O netblame não enxerga o tráfego UDP do jogo em si.** As sondas UDP vão para resolvedores
  públicos (1.1.1.1 e 8.8.8.8), não para o servidor da sua partida. Elas mostram se a rede trata UDP
  pior que ping, mas uma rota ruim até um servidor de jogo específico só aparece via alvo TCP do app
  e via tabela de saltos. Ler os pacotes reais do jogo exige captura de pacotes, que precisa de
  administrador (veja o roadmap). Uma captura limpa é uma evidência forte, não uma prova. Rode
  *enquanto* o problema acontece, e por mais tempo.
- O alvo do app checa a "porta da frente" TCP do serviço (`battle.net:443`), e não o servidor
  específico da partida.
- Muitos provedores interceptam o DNS (porta 53). Nesse caso, o teste UDP mede o servidor DNS do
  provedor, e não o caminho até 1.1.1.1/8.8.8.8. O netblame detecta isso (DNS muito mais lento que o
  ping ao mesmo IP) e avisa no relatório.
- A detecção de "queda do jogo" usa a CPU do processo: ela não separa uma queda de um fim de partida
  normal. Por isso o relatório diz "terminou ou caiu".
- Os contadores UDP do Windows são da máquina inteira. Eles mostram *que* houve descarte, não *qual*
  programa perdeu os pacotes.
- As estatísticas por salto via ICMP só são tão honestas quanto os roteadores que respondem. A regra
  de rate-limit resolve o caso comum, mas, vendo de fora, não dá para separar um roteador que
  despriorizou ICMP *e* tem perda real.
- Por enquanto, só IPv4.
- Os limiares (1% de perda, CPU 90%, p95 > 4× a mediana...) são heurísticas, definidas como constantes
  no topo de [`netblame/analysis.py`](netblame/analysis.py).

## Desenvolvimento

```powershell
pip install -e .[dev,system]
pytest
```

O parsing é separado da execução: são funções puras, testadas com saídas reais do Windows em pt-BR e
en-US. Por isso a suíte de testes roda em qualquer sistema. Cada cenário do demo tem um teste que
confere se a análise chega ao veredito esperado.

```
netblame/
  models.py     dataclasses + persistência em JSON (Session, Sample, SysSample, UdpSample, HopStat...)
  i18n.py       Text bilíngue (en/pt), formatação de números por idioma, detecção do idioma
  probes.py     sondas de ping / TCP / DNS cru, parser de ping independente de idioma, contadores UDP
  netinfo.py    gateway (route print), servidores DNS (registro), snapshot das placas físicas
  tracing.py    parser do tracert, monitor por salto, find_bad_hop / detecção de rate-limit
  sysmon.py     CPU, RAM, tráfego, processo monitorado (psutil)
  collector.py  o loop de captura em paralelo
  analysis.py   estatísticas, apagões, regras → findings → veredito
  demo.py       cenários sintéticos reprodutíveis
  report.py     relatório HTML/SVG autocontido
  cli.py        run | report | demo
```

## Roadmap

- **Captura do tráfego real do jogo** (modo opcional com administrador, via `pktmon`/ETW): descobrir o
  IP do servidor da partida, sondá-lo diretamente e detectar "silêncios" no fluxo UDP do jogo
- **Notificações**: um aviso na área de trabalho quando um apagão começa, com o local provável
- **Histórico de sessões**: comparar capturas de dias e horários diferentes para achar
  congestionamento do provedor no horário de pico
- Suporte a IPv6

## Licença

MIT
