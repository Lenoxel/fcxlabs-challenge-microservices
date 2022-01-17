import { forwardRef, Global, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { UserRepository } from './repositories/user.repository';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { ElasticSearchModule } from './elastic-search/elastic-search.module';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from 'apps/auth/src/auth.module';

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRoot({
      type: 'mysql',
      host: 'mysql_user',
      database: 'users',
      port: 3306,
      username: 'root',
      password: 'root',
      entities: [User],
      synchronize: false,
      autoLoadEntities: true,
      dropSchema: false,
      migrationsRun: false,
      logging: ['warn', 'error'],
      cli: {
        migrationsDir: 'apps/user/src/migrations',
      },
    }),
    TypeOrmModule.forFeature([UserRepository]),
    ElasticSearchModule,
    forwardRef(() => AuthModule),
  ],
  providers: [UserService],
  controllers: [UserController],
  exports: [UserService],
})
export class UserModule {}
