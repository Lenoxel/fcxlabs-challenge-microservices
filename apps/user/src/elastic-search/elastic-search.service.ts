import { Injectable } from '@nestjs/common';
import { ElasticsearchService } from '@nestjs/elasticsearch';
import { User } from '../entities/user.entity';
import { UserSearchBody } from './interfaces/userSearchBody.type';
import { UserSearchResult } from './interfaces/userSearchResult.type';

@Injectable()
export class ElasticSearchService {
  constructor(private readonly elasticsearchService: ElasticsearchService) {}

  async search(text: string, fields: string[]): Promise<UserSearchBody[]> {
    const { body } = await this.elasticsearchService.search<UserSearchResult>({
      index: 'users',
      body: {
        query: {
          multi_match: {
            query: text,
            fields,
          },
        },
      },
    });
    const hits = body.hits.hits;
    return hits.map((item) => item._source);
  }

  async index({ id, name, login, cpf, status, birthDate }: User) {
    return await this.elasticsearchService.index({
      index: 'users',
      body: {
        id,
        name,
        login,
        cpf,
        status,
        birthDate,
      },
    });
  }

  async update(user: User) {
    await this.remove(user.id);
    await this.index(user);
  }

  async remove(userId: string) {
    this.elasticsearchService.deleteByQuery({
      index: 'users',
      body: {
        query: {
          match: {
            id: userId,
          },
        },
      },
    });
  }
}
