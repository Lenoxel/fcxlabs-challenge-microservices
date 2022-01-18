# FCxLabs Challenge

## Descrição

O projeto foi construído utilizando o framework Nest.js, tomando proveito das libs e built-ins que o mesmo fornece para resolver os desafios propostos e implementar toda a API Restful.

A API Restful foi arquiteturada no modelo de microservices, em um monorepo, com o objetivo de facilitar o gerenciamento das bibliotecas e dos domínios da aplicação, possibilitando que cada microservice escale individualmente e possam ser acessados a partir de um mesmo diretório/repositório.

Os domínios da aplicação são:

1 - auth: responsável pela autenticação e autorização da aplicação.

2 - user: responsável pela criação dos usuários que têm acesso à aplicação, provendo todos os outros endpoints necessários para atender os requisitos do sistema.

A estrutura do projeto segue boa parte do que já é sugerido pelo nest.js, visto que é um framework opinativo e já indica o caminho que cada coisa "deve" ficar.

Aqui, vale ressaltar os seguintes arquivos e pastas:

1 - main.ts: ponto de partida do projeto, onde o backend feito em nest é inicializado.

2 - controller: recebe as chamadas feitas por http (API, frontend, etc.) e as delega para os respectivos services.

3 - service: cuida das regras de negócio e casos de uso da aplicação.

4 - repository: responsável pela comunicação com o banco de dados através do paradigma de orientação a objetos: design pattern + typeorm.

5 - jwt: pasta da aplicação auth que é responsável por implementar o jwt através das features do próprio nest.js.

## Base de Dados

Foi criado um server MySQL 8.0, onde temos o schema "users" e, consequentemente, a tabela "user", que armazena todos os usuários cadastrados no sistema.

Embora todo esse processo tenha sido automatizado, com a criação de um container docker a partir de uma imagem MySQL, e também com ORM (Typeorm) por parte do backend, abaixo segue o script de criação da tabela "user":

```bash
create table users.user
(
    id          varchar(36)                               not null
        primary key,
    name        varchar(255)                              not null,
    login       varchar(255)                              not null,
    password    varchar(255)                              not null,
    email       varchar(255)                              not null,
    phoneNumber varchar(255)                              not null,
    cpf         varchar(255)                              not null,
    birthDate   date                                      not null,
    motherName  varchar(255)                              not null,
    status      enum ('Ativo', 'Bloqueado', 'Inativo')    not null,
    createdAt   timestamp    default CURRENT_TIMESTAMP    not null,
    updatedAt   timestamp(6) default CURRENT_TIMESTAMP(6) not null on update CURRENT_TIMESTAMP(6),
    constraint IDX_a6235b5ef0939d8deaad755fc8
        unique (cpf),
    constraint IDX_e12875dfb3b1d92d7d7c5377e2
        unique (email)
);
```

## Requisitos para rodar a aplicação

Para rodar o projeto localmente, é necessário utilizar: Docker, Docker-Compose, Node e NPM.

Na minha máquina, as versões utilizadas durante o desenvolvimento foram: Docker - 20.10.12; docker-compose - 1.26.0; Node - 14.8.2; NPM - 6.14.15.

## Instalação e execução da aplicação

Antes de rodar o comando abaixo, certifique-se de deixar livres as portas que serão utilizadas para servir a aplicação: 3000 (users), 3001 (auth) e 33306 (mysql), sendo todas no domínio localhost.

Na pasta raiz do projeto, execute:

```bash
# Caso deseje acompanhar os servidores pelo terminal, não utilizar o alias "-d"
$ docker-compose up -d
```

## Testar a aplicação

Para visualizar as chamadas nos endpoints da aplicação, sugiro a importação do arquivo "FCxLabs Challenge.postman_collection.json", que está na pasta raiz do projeto, para dentro do Postman. Esse arquivo contém todas as chamadas possíveis da API, com alguns exemplos já inseridos.

# Sobre o Nest.js

## Support

Nest is an MIT-licensed open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

## Stay in touch

- Author - [Kamil Myśliwiec](https://kamilmysliwiec.com)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## License

Nest is [MIT licensed](LICENSE).

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo_text.svg" width="320" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

  <p align="center">A progressive <a href="http://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/dm/@nestjs/common.svg" alt="NPM Downloads" /></a>
<a href="https://circleci.com/gh/nestjs/nest" target="_blank"><img src="https://img.shields.io/circleci/build/github/nestjs/nest/master" alt="CircleCI" /></a>
<a href="https://coveralls.io/github/nestjs/nest?branch=master" target="_blank"><img src="https://coveralls.io/repos/github/nestjs/nest/badge.svg?branch=master#9" alt="Coverage" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer" target="_blank"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor" target="_blank"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec" target="_blank"><img src="https://img.shields.io/badge/Donate-PayPal-ff3f59.svg"/></a>
    <a href="https://opencollective.com/nest#sponsor"  target="_blank"><img src="https://img.shields.io/badge/Support%20us-Open%20Collective-41B883.svg" alt="Support us"></a>
  <a href="https://twitter.com/nestframework" target="_blank"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->