# Wazuh SIEM - Servidor de Monitorizacao e Deteccao de Ameacas

Implementacao de um SIEM (Security Information and Event Management) open-source num servidor domestico real, com deteccao de vulnerabilidades, monitorizacao de integridade de ficheiros (FIM) e mapeamento automatico para o framework MITRE ATT&CK, usando dados reais de ataques recebidos pela internet.

## Contexto

Projeto 5 do meu percurso de portfolio em ciberseguranca, desenvolvido no ambito do estagio curricular em IT/Ciberseguranca na Escola Superior Agraria de Coimbra (ESAC), integrado no CET Tecnico Especialista de Ciberseguranca do IEFP Coimbra.

O objetivo foi implementar um SIEM funcional, capaz de monitorizar multiplos endpoints (o proprio servidor Linux e um posto Windows 11), de forma isolada e segura, sem expor a interface de gestao publicamente.

## Arquitetura

- **Wazuh 4.14.6**, implementado via Docker Compose (deployment single-node oficial)
- **2 agentes ativos**: o proprio servidor Ubuntu 24.04 (`helderlab-server`) e um posto Windows 11 Pro (`WIN11HS-CLIENT`)
- **Isolamento de rede**: todas as portas do Wazuh (dashboard, indexer, manager) estao vinculadas apenas a VPN WireGuard (10.0.0.1) e a rede local de casa (192.168.1.0/24), nunca expostas ao IP publico, com regras UFW explicitas para cada porta

## Decisao de seguranca: isolamento por rede

Ao expor o Wazuh via Docker, foi identificado que o Docker manipula o iptables diretamente, contornando as regras UFW por defeito. Isto significava que, sem correcao, as portas do Wazuh (8443, 9200, 55000, 1514-1515, 514) ficariam acessiveis publicamente na internet, apesar do UFW estar configurado com "deny by default".

Correcao aplicada: vinculacao explicita de cada porta aos IPs da VPN e da rede local no `docker-compose.yml`, complementada com regras UFW especificas para essas sub-redes. Isto garante que o SIEM, que gere dados sensiveis do proprio servidor, nunca fica acessivel a partir da internet publica.

## Modulos configurados

- **File Integrity Monitoring (FIM)**: monitoriza alteracoes em `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/boot`, com deteccao de ficheiros adicionados, modificados e removidos
- **Vulnerability Detection**: inventaria pacotes instalados e cruza com bases de dados de CVEs
- **MITRE ATT&CK**: mapeamento automatico de alertas para taticas e tecnicas de ataque conhecidas

## Cobertura MITRE ATT&CK (dados reais)

Como o servidor tem SSH exposto publicamente (necessario para acesso remoto), recebe ataques reais e continuos de bots na internet. Em vez de simular ataques artificialmente, este projeto documenta a deteccao real:

| Tatica | Alertas |
|---|---|
| Credential Access | 16219 |
| Lateral Movement | 9096 |
| Defense Evasion | 4790 |
| Impact | 3015 |
| Privilege Escalation | 537 |
| Persistence | 297 |
| Initial Access | 278 |

**17 tecnicas distintas** foram detectadas automaticamente, incluindo T1110.001 (Password Guessing, 16203 alertas) e T1021 (Remote Services, SSH, 9078 alertas).

**Top 3 IPs mais agressivos identificados:**

| IP | Tentativas |
|---|---|
| 62.60.130.237 | 2786 |
| 165.1.78.209 | 2374 |
| 195.178.110.137 | 1088 |

Estes dados sao complementados pelo Fail2ban, que ja tinha bloqueado 2490 IPs e registado 13131 tentativas falhadas de login antes mesmo desta analise.

## Caso pratico: interpretar nomes tecnicos alarmantes

Durante a analise, a tecnica "Data Destruction" apareceu com 918 ocorrencias, um nome que soa grave. Investigacao directa ao evento revelou tratar-se da remocao rotineira de ficheiros temporarios `.mount` do snapd durante atualizacoes normais do sistema, nao qualquer atividade maliciosa. O MITRE classifica pela accao tecnica (ficheiro apagado), nao pela intencao. Este caso reforca a importancia de investigar o contexto antes de reagir a um nome de tecnica alarmante.

## Caso pratico: diagnostico do FIM

Ao testar manualmente a deteccao de "ficheiro adicionado" atraves de `touch` seguido de restart do agente, os alertas nao apareciam de imediato. Investigacao revelou que o `scan_on_start` (executado apos cada restart) nao gera alertas de imediato por desenho, para evitar tempestades de alertas ao reiniciar o servico; a deteccao real ocorre no scan periodico seguinte. Confirmado atraves de consulta direta ao indice `wazuh-alerts-*`, onde se encontraram 7 alertas reais de "File added" no servidor, incluindo a instalacao do `sqlite3` feita durante este mesmo projeto.

## Scripts

- `scripts/mitre_coverage.py` - consulta o Wazuh Indexer e gera um relatorio de cobertura MITRE ATT&CK (taticas, tecnicas, e top IPs de origem de brute-force), a partir de dados reais

## Instalacao

Ver a documentacao oficial do Wazuh Docker single-node: https://github.com/wazuh/wazuh-docker

Resumo dos passos seguidos:
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.6 --depth=1
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d

Depois, editar o `docker-compose.yml` para vincular as portas aos IPs de rede local/VPN, e aplicar as regras UFW correspondentes antes de iniciar os containers.

## Tecnologias

- Wazuh 4.14.6 (Docker)
- OpenSearch (Wazuh Indexer)
- Python 3 (requests, para consulta a API do indexer)
- UFW, Fail2ban

## Capturas de ecra

Ver pasta `screenshots/`. Inclui: dashboard geral, lista de agentes ativos, estado dos containers Docker, regras de isolamento UFW, e output do relatorio de cobertura MITRE ATT&CK.

## Autor

Helder Sindique
[LinkedIn](https://www.linkedin.com/in/helder-luis-sindique-69223331/) | [Portfolio](https://heldersindique.pt)
