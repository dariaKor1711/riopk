# Примеры проблемного кода и их исправления

## Содержание

1. [Архитектурные проблемы](#архитектурные-проблемы)
2. [Проблемы Dependency Injection в NestJS](#проблемы-dependency-injection-в-nestjs)
3. [Утечки памяти и производительность](#утечки-памяти-и-производительность)
4. [Проблемы с асинхронным кодом](#проблемы-с-асинхронным-кодом)
5. [Нарушение принципов Clean Architecture](#нарушение-принципов-clean-architecture)

---

## Архитектурные проблемы

### Проблема 1: Нарушение Single Responsibility Principle (SRP)

**Проблемный код:**

```typescript
// Плохо: один сервис отвечает за слишком много задач
@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private userRepo: Repository<User>,
    private emailService: EmailService,
    private loggerService: LoggerService,
    private paymentService: PaymentService
  ) {}

  async createUser(userData: CreateUserDto) {
    // Валидация данных
    if (!userData.email || !userData.password) {
      throw new BadRequestException('Missing required fields');
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(userData.password, 10);

    // Создание пользователя
    const user = await this.userRepo.save({
      ...userData,
      password: hashedPassword,
    });

    // Отправка welcome email
    await this.emailService.sendWelcomeEmail(user.email);

    // Создание платежного профиля
    await this.paymentService.createPaymentProfile(user.id);

    // Логирование
    this.loggerService.log(`User created: ${user.id}`);

    // Генерация JWT токена
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);

    return { user, token };
  }
}
```

**Исправленный код (Clean Architecture + DDD):**

```typescript
//  Хорошо: разделение ответственности по принципам Clean Architecture

// Domain Layer - Сущность пользователя
export class User {
  constructor(
    public readonly id: UserId,
    public readonly email: Email,
    private readonly passwordHash: PasswordHash,
    public readonly createdAt: Date
  ) {}

  static create(email: string, password: string): User {
    // Доменная логика валидации
    const emailVo = Email.create(email);
    const passwordVo = PasswordHash.create(password);

    return new User(UserId.generate(), emailVo, passwordVo, new Date());
  }
}

// Application Layer - Use Case
@Injectable()
export class CreateUserUseCase {
  constructor(
    private readonly userRepository: IUserRepository,
    private readonly passwordHasher: IPasswordHasher,
    private readonly eventBus: IEventBus
  ) {}

  async execute(command: CreateUserCommand): Promise<CreateUserResult> {
    // Создание пользователя через доменную логику
    const user = User.create(command.email, command.password);

    // Сохранение через репозиторий
    await this.userRepository.save(user);

    // Публикация доменного события
    await this.eventBus.publish(new UserCreatedEvent(user.id, user.email));

    return CreateUserResult.success(user.id);
  }
}

// Infrastructure Layer - Контроллер
@Controller('users')
export class UserController {
  constructor(private readonly createUserUseCase: CreateUserUseCase) {}

  @Post()
  async createUser(@Body() dto: CreateUserDto) {
    const command = new CreateUserCommand(dto.email, dto.password);
    const result = await this.createUserUseCase.execute(command);

    if (result.isFailure()) {
      throw new BadRequestException(result.error);
    }

    return { userId: result.value };
  }
}

// Event Handlers - отдельная ответственность
@EventHandler(UserCreatedEvent)
export class UserCreatedHandler {
  constructor(
    private readonly emailService: EmailService,
    private readonly paymentService: PaymentService
  ) {}

  async handle(event: UserCreatedEvent) {
    await Promise.all([
      this.emailService.sendWelcomeEmail(event.email),
      this.paymentService.createPaymentProfile(event.userId),
    ]);
  }
}
```

---

## Проблемы Dependency Injection в NestJS

### Проблема 2: Циклические зависимости и неправильная область видимости

**Проблемный код:**

```typescript
// Плохо: циклическая зависимость и неправильное использование Singleton
@Injectable()
export class UserService {
  private cache = new Map(); // Потенциальная утечка памяти

  constructor(
    private orderService: OrderService // Циклическая зависимость
  ) {}

  async getUserWithOrders(userId: string) {
    if (this.cache.has(userId)) {
      return this.cache.get(userId); // Никогда не очищается
    }

    const user = await this.findById(userId);
    const orders = await this.orderService.getOrdersByUserId(userId);

    const result = { ...user, orders };
    this.cache.set(userId, result); // Растет бесконечно

    return result;
  }
}

@Injectable()
export class OrderService {
  constructor(
    private userService: UserService // Циклическая зависимость
  ) {}

  async getOrdersByUserId(userId: string) {
    const user = await this.userService.findById(userId); // Потенциальная рекурсия
    // ... логика
  }
}
```

**Исправленный код:**

```typescript
//  Хорошо: разрыв циклических зависимостей через интерфейсы

// Domain Layer - интерфейсы
export interface IUserRepository {
  findById(id: UserId): Promise<User | null>;
}

export interface IOrderRepository {
  findByUserId(userId: UserId): Promise<Order[]>;
}

// Application Layer - Use Case без циклических зависимостей
@Injectable()
export class GetUserWithOrdersUseCase {
  constructor(
    private readonly userRepository: IUserRepository,
    private readonly orderRepository: IOrderRepository,
    @Inject('CACHE_MANAGER') private readonly cacheManager: Cache
  ) {}

  async execute(query: GetUserWithOrdersQuery): Promise<UserWithOrdersResult> {
    const cacheKey = `user-orders-${query.userId}`;

    // Правильная работа с кешем
    let result = await this.cacheManager.get<UserWithOrdersResult>(cacheKey);

    if (!result) {
      const [user, orders] = await Promise.all([
        this.userRepository.findById(UserId.from(query.userId)),
        this.orderRepository.findByUserId(UserId.from(query.userId)),
      ]);

      if (!user) {
        return UserWithOrdersResult.notFound();
      }

      result = UserWithOrdersResult.success(user, orders);

      // Кеш с TTL
      await this.cacheManager.set(cacheKey, result, 300); // 5 минут
    }

    return result;
  }
}

// Infrastructure Layer - правильная конфигурация модулей
@Module({
  imports: [
    CacheModule.register({
      ttl: 300, // TTL по умолчанию
      max: 1000, // Максимум элементов в кеше
    }),
  ],
  providers: [
    GetUserWithOrdersUseCase,
    {
      provide: 'IUserRepository',
      useClass: TypeOrmUserRepository,
    },
    {
      provide: 'IOrderRepository',
      useClass: TypeOrmOrderRepository,
    },
  ],
})
export class UserModule {}
```

---

## Утечки памяти и производительность

### Проблема 3: Event Listeners и утечки памяти

**Проблемный код:**

```typescript
// Плохо: не удаляются event listeners, блокировка Event Loop
@Injectable()
export class DataProcessingService {
  private intervals: NodeJS.Timeout[] = [];
  private eventEmitter = new EventEmitter();

  constructor() {
    // Утечка памяти - listener никогда не удаляется
    this.eventEmitter.on('data', this.processData.bind(this));

    // Потенциальная утечка - interval не очищается
    const interval = setInterval(() => {
      this.heavyComputation(); // Блокирует Event Loop
    }, 1000);

    this.intervals.push(interval);
  }

  private processData(data: any[]) {
    // Синхронная обработка больших массивов - блокирует Event Loop
    return data.map(item => {
      // Тяжелые вычисления
      for (let i = 0; i < 1000000; i++) {
        Math.sqrt(i);
      }
      return this.transformItem(item);
    });
  }

  private heavyComputation() {
    // Блокирующая операция
    const result = [];
    for (let i = 0; i < 10000000; i++) {
      result.push(Math.random());
    }
    return result;
  }
}
```

**Исправленный код:**

```typescript
//  Хорошо: правильное управление ресурсами и неблокирующие операции

@Injectable()
export class DataProcessingService implements OnModuleDestroy {
  private intervals: NodeJS.Timeout[] = [];
  private eventEmitter = new EventEmitter();
  private abortController = new AbortController();

  constructor(@Inject('LOGGER') private readonly logger: Logger) {
    this.setupEventHandlers();
    this.startPeriodicTasks();
  }

  private setupEventHandlers() {
    // Правильная настройка с возможностью очистки
    const handler = this.processDataAsync.bind(this);
    this.eventEmitter.on('data', handler);

    // Сохраняем ссылку для очистки
    this.eventEmitter.once('cleanup', () => {
      this.eventEmitter.removeListener('data', handler);
    });
  }

  private async processDataAsync(data: any[]): Promise<any[]> {
    // Асинхронная обработка с батчингом
    const batchSize = 100;
    const results = [];

    for (let i = 0; i < data.length; i += batchSize) {
      if (this.abortController.signal.aborted) {
        break;
      }

      const batch = data.slice(i, i + batchSize);

      // Используем setImmediate для передачи управления Event Loop
      const batchResult = await new Promise<any[]>(resolve => {
        setImmediate(() => {
          const processed = batch.map(item => this.transformItem(item));
          resolve(processed);
        });
      });

      results.push(...batchResult);

      // Даем Event Loop обработать другие задачи
      await this.sleep(0);
    }

    return results;
  }

  private startPeriodicTasks() {
    const interval = setInterval(async () => {
      if (this.abortController.signal.aborted) {
        clearInterval(interval);
        return;
      }

      try {
        await this.heavyComputationAsync();
      } catch (error) {
        this.logger.error('Error in periodic task:', error);
      }
    }, 1000);

    this.intervals.push(interval);
  }

  private async heavyComputationAsync(): Promise<number[]> {
    // Разбиваем тяжелую операцию на части
    return new Promise((resolve, reject) => {
      const result: number[] = [];
      const chunkSize = 100000;
      let processed = 0;
      const total = 10000000;

      const processChunk = () => {
        const end = Math.min(processed + chunkSize, total);

        for (let i = processed; i < end; i++) {
          result.push(Math.random());
        }

        processed = end;

        if (processed < total) {
          // Передаем управление Event Loop
          setImmediate(processChunk);
        } else {
          resolve(result);
        }
      };

      processChunk();
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Правильная очистка ресурсов
  async onModuleDestroy() {
    this.abortController.abort();
    this.eventEmitter.emit('cleanup');

    this.intervals.forEach(interval => clearInterval(interval));
    this.intervals = [];

    this.eventEmitter.removeAllListeners();
  }
}
```

---

## Проблемы с асинхронным кодом

### Проблема 4: Неправильная обработка ошибок и Promise hell

**Проблемный код:**

```typescript
// Плохо: Promise hell, неправильная обработка ошибок
@Injectable()
export class OrderService {
  async processOrder(orderId: string) {
    return this.getOrder(orderId)
      .then(order => {
        return this.validateOrder(order).then(isValid => {
          if (isValid) {
            return this.calculatePrice(order).then(price => {
              return this.processPayment(order, price).then(paymentResult => {
                if (paymentResult.success) {
                  return this.updateInventory(order).then(() => {
                    return this.sendConfirmation(order)
                      .then(() => {
                        return { success: true, order };
                      })
                      .catch(error => {
                        // Ошибка при отправке подтверждения игнорируется
                        return { success: true, order };
                      });
                  });
                } else {
                  throw new Error('Payment failed');
                }
              });
            });
          } else {
            throw new Error('Invalid order');
          }
        });
      })
      .catch(error => {
        // Общая обработка всех ошибок - теряется контекст
        throw new InternalServerErrorException('Order processing failed');
      });
  }

  private async processPayment(order: any, price: number) {
    // Отсутствует timeout - может висеть бесконечно
    return fetch('/payment-api', {
      method: 'POST',
      body: JSON.stringify({ orderId: order.id, amount: price }),
    }).then(response => response.json());
  }
}
```

**Исправленный код:**

```typescript
//  Хорошо: правильная обработка асинхронного кода

@Injectable()
export class OrderService {
  constructor(
    @Inject('HTTP_CLIENT') private readonly httpClient: HttpClient,
    @Inject('LOGGER') private readonly logger: Logger
  ) {}

  async processOrder(orderId: string): Promise<ProcessOrderResult> {
    try {
      // Используем async/await вместо Promise chains
      const order = await this.getOrder(orderId);

      const isValid = await this.validateOrder(order);
      if (!isValid) {
        return ProcessOrderResult.failure('INVALID_ORDER', 'Order validation failed');
      }

      const price = await this.calculatePrice(order);

      // Обработка критических и некритических операций отдельно
      const paymentResult = await this.processPaymentWithRetry(order, price);
      if (!paymentResult.success) {
        return ProcessOrderResult.failure('PAYMENT_FAILED', paymentResult.error);
      }

      // Критические операции с транзакционностью
      await this.updateInventory(order);

      // Некритические операции не должны ломать основной флоу
      this.sendConfirmationAsync(order).catch(error => {
        this.logger.warn(`Failed to send confirmation for order ${orderId}:`, error);
        // Можно добавить в очередь для повторной отправки
      });

      return ProcessOrderResult.success(order);
    } catch (error) {
      this.logger.error(`Order processing failed for ${orderId}:`, error);

      // Специфичная обработка разных типов ошибок
      if (error instanceof OrderNotFoundError) {
        return ProcessOrderResult.failure('ORDER_NOT_FOUND', 'Order not found');
      }

      if (error instanceof InventoryError) {
        return ProcessOrderResult.failure('INVENTORY_ERROR', 'Insufficient inventory');
      }

      return ProcessOrderResult.failure('INTERNAL_ERROR', 'Internal processing error');
    }
  }

  private async processPaymentWithRetry(
    order: Order,
    price: number,
    maxRetries: number = 3
  ): Promise<PaymentResult> {
    const controller = new AbortController();

    // Таймаут для предотвращения зависания
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 секунд

    try {
      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          const result = await this.httpClient.post('/payment-api', {
            body: { orderId: order.id, amount: price },
            signal: controller.signal,
            timeout: 10000, // 10 секунд на каждый запрос
          });

          return PaymentResult.success(result.data);
        } catch (error) {
          this.logger.warn(`Payment attempt ${attempt} failed:`, error);

          if (attempt === maxRetries) {
            throw error;
          }

          // Экспоненциальная задержка между попытками
          await this.sleep(Math.pow(2, attempt) * 1000);
        }
      }
    } finally {
      clearTimeout(timeoutId);
    }

    return PaymentResult.failure('MAX_RETRIES_EXCEEDED');
  }

  private async sendConfirmationAsync(order: Order): Promise<void> {
    // Асинхронная отправка без блокировки основного флоу
    setImmediate(async () => {
      try {
        await this.emailService.sendOrderConfirmation(order);
        await this.smsService.sendOrderSms(order);
      } catch (error) {
        this.logger.error('Confirmation sending failed:', error);
        // Можно добавить в очередь для повторной отправки
        await this.addToRetryQueue('send_confirmation', { orderId: order.id });
      }
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Value Objects для типизированных результатов
export class ProcessOrderResult {
  private constructor(
    public readonly isSuccess: boolean,
    public readonly data?: Order,
    public readonly errorCode?: string,
    public readonly errorMessage?: string
  ) {}

  static success(order: Order): ProcessOrderResult {
    return new ProcessOrderResult(true, order);
  }

  static failure(code: string, message: string): ProcessOrderResult {
    return new ProcessOrderResult(false, undefined, code, message);
  }
}
```

---

## Нарушение принципов Clean Architecture

### Проблема 5: Смешивание слоев архитектуры

**Проблемный код:**

```typescript
// Плохо: смешивание всех слоев в одном контроллере
@Controller('products')
export class ProductController {
  constructor(
    @InjectRepository(Product) private productRepo: Repository<Product>,
    private httpService: HttpService
  ) {}

  @Get(':id')
  async getProduct(@Param('id') id: string, @Res() res: Response) {
    try {
      // Прямое обращение к БД из контроллера (нарушение Clean Architecture)
      const product = await this.productRepo
        .createQueryBuilder('product')
        .leftJoinAndSelect('product.category', 'category')
        .where('product.id = :id', { id })
        .getOne();

      if (!product) {
        return res.status(404).json({ error: 'Product not found' });
      }

      // Бизнес-логика в контроллере
      if (product.price > 1000) {
        product.isPremium = true;
      }

      // Внешний API вызов из контроллера
      const exchangeRate = await this.httpService
        .get('https://api.exchangerate-api.com/v4/latest/USD')
        .toPromise();

      product.priceInEur = product.price * exchangeRate.data.rates.EUR;

      // Прямая работа с HTTP response
      res.json(product);
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}
```

**Исправленный код (Clean Architecture):**

```typescript
//  Хорошо: правильное разделение по слоям Clean Architecture

// Domain Layer - Сущности и бизнес-логика
export class Product {
  constructor(
    public readonly id: ProductId,
    public readonly name: string,
    public readonly price: Money,
    public readonly category: Category
  ) {}

  isPremium(): boolean {
    // Бизнес-логика в доменной модели
    return this.price.amount > 1000;
  }

  convertToEur(exchangeRate: number): Money {
    return new Money(this.price.amount * exchangeRate, 'EUR');
  }
}

export class Money {
  constructor(public readonly amount: number, public readonly currency: string) {
    if (amount < 0) {
      throw new Error('Amount cannot be negative');
    }
  }
}

// Domain Layer - Интерфейсы репозиториев
export interface IProductRepository {
  findById(id: ProductId): Promise<Product | null>;
}

export interface IExchangeRateService {
  getRate(from: string, to: string): Promise<number>;
}

// Application Layer - Use Cases
@Injectable()
export class GetProductUseCase {
  constructor(
    private readonly productRepository: IProductRepository,
    private readonly exchangeRateService: IExchangeRateService
  ) {}

  async execute(query: GetProductQuery): Promise<GetProductResult> {
    const product = await this.productRepository.findById(query.productId);

    if (!product) {
      return GetProductResult.notFound();
    }

    let productWithEurPrice = product;

    // Получаем курс валют если нужно
    if (query.includeEurPrice) {
      try {
        const exchangeRate = await this.exchangeRateService.getRate('USD', 'EUR');
        const eurPrice = product.convertToEur(exchangeRate);
        productWithEurPrice = { ...product, eurPrice };
      } catch (error) {
        // Если не удалось получить курс, возвращаем без EUR цены
        // Не ломаем основной флоу из-за внешней зависимости
      }
    }

    return GetProductResult.success(productWithEurPrice);
  }
}

// Application Layer - DTOs
export class GetProductQuery {
  constructor(
    public readonly productId: ProductId,
    public readonly includeEurPrice: boolean = false
  ) {}
}

export class GetProductResult {
  private constructor(
    public readonly isSuccess: boolean,
    public readonly product?: Product & { eurPrice?: Money },
    public readonly errorCode?: string
  ) {}

  static success(product: Product & { eurPrice?: Money }): GetProductResult {
    return new GetProductResult(true, product);
  }

  static notFound(): GetProductResult {
    return new GetProductResult(false, undefined, 'PRODUCT_NOT_FOUND');
  }
}

// Infrastructure Layer - Реализация репозитория
@Injectable()
export class TypeOrmProductRepository implements IProductRepository {
  constructor(@InjectRepository(ProductEntity) private productRepo: Repository<ProductEntity>) {}

  async findById(id: ProductId): Promise<Product | null> {
    const entity = await this.productRepo
      .createQueryBuilder('product')
      .leftJoinAndSelect('product.category', 'category')
      .where('product.id = :id', { id: id.value })
      .getOne();

    return entity ? this.toDomain(entity) : null;
  }

  private toDomain(entity: ProductEntity): Product {
    return new Product(
      new ProductId(entity.id),
      entity.name,
      new Money(entity.price, 'USD'),
      new Category(entity.category.id, entity.category.name)
    );
  }
}

// Infrastructure Layer - Внешний сервис
@Injectable()
export class ExchangeRateApiService implements IExchangeRateService {
  constructor(private readonly httpService: HttpService) {}

  async getRate(from: string, to: string): Promise<number> {
    const response = await this.httpService
      .get(`https://api.exchangerate-api.com/v4/latest/${from}`, {
        timeout: 5000,
      })
      .toPromise();

    return response.data.rates[to];
  }
}

// Presentation Layer - Контроллер (тонкий слой)
@Controller('products')
@ApiTags('products')
export class ProductController {
  constructor(private readonly getProductUseCase: GetProductUseCase) {}

  @Get(':id')
  @ApiOperation({ summary: 'Get product by ID' })
  @ApiParam({ name: 'id', description: 'Product ID' })
  @ApiQuery({ name: 'includeEur', required: false, type: Boolean })
  async getProduct(
    @Param('id') id: string,
    @Query('includeEur') includeEur: boolean = false
  ): Promise<ProductResponseDto> {
    const query = new GetProductQuery(new ProductId(id), includeEur);
    const result = await this.getProductUseCase.execute(query);

    if (!result.isSuccess) {
      throw new NotFoundException('Product not found');
    }

    return this.toResponseDto(result.product!);
  }

  private toResponseDto(product: Product & { eurPrice?: Money }): ProductResponseDto {
    return {
      id: product.id.value,
      name: product.name,
      price: product.price.amount,
      currency: product.price.currency,
      isPremium: product.isPremium(),
      category: product.category.name,
      eurPrice: product.eurPrice?.amount,
    };
  }
}

// Infrastructure Layer - Модуль с правильной конфигурацией DI
@Module({
  imports: [
    TypeOrmModule.forFeature([ProductEntity]),
    HttpModule.register({
      timeout: 5000,
      maxRedirects: 3,
    }),
  ],
  controllers: [ProductController],
  providers: [
    GetProductUseCase,
    {
      provide: 'IProductRepository',
      useClass: TypeOrmProductRepository,
    },
    {
      provide: 'IExchangeRateService',
      useClass: ExchangeRateApiService,
    },
  ],
})
export class ProductModule {}
```

---

## Заключение

Представленные примеры демонстрируют типичные проблемы, возникающие при разработке на Node.js/NestJS/TypeScript, и способы их решения с использованием принципов Clean Architecture и DDD:

1. **Разделение ответственности** - каждый класс отвечает за одну задачу
2. **Инверсия зависимостей** - зависимость от абстракций, а не от конкретных реализаций
3. **Правильное управление ресурсами** - предотвращение утечек памяти
4. **Неблокирующие операции** - сохранение отзывчивости Event Loop
5. **Обработка ошибок** - специфичная обработка разных типов ошибок
6. **Слоистая архитектура** - четкое разделение между слоями приложения

Эти подходы позволяют создавать масштабируемые, тестируемые и поддерживаемые приложения.
