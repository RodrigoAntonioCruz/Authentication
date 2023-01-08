package br.com.appodontologia.util;

public class Constants {

    /**
     * LOG_KEY
     */
    public static final String X_TRACEID = "X-traceid";
    public static final String LOG_KEY_CLASS = "class={} ";
    public static final String LOG_KEY_METHOD = "method={} ";

    public static final String LOG_KEY_MESSAGE = "msg=\"{}\" ";
    public static final String LOG_KEY_CAUSE = "cause=\"{}\" ";

    public static final String LOG_KEY_ENTITY = "entity=\"{}\" ";

    public static final String LOG_KEY_ENTITY_ID = "entityId={} ";
    public static final String LOG_KEY_REGION = "region={} ";

    public static final String LOG_KEY_SCORE = "score={} ";

    public static final String LOG_METHOD_AUTHENTICATE = "authenticate";
    public static final String LOG_METHOD_REGISTER = "register";


    /**
     * LOG_CLASS
     */
    public static final String LOG_CLASS_AFFINITY_CONTROLLER = "AfinidadeController";
    public static final String LOG_CLASS_SCORE_CONTROLLER = "ScoreController";
    public static final String LOG_CLASS_PERSON_CONTROLLER = "PessoaController";
    public static final String LOG_CLASS_USER_CONTROLLER = "UsuarioController";

    public static final String LOG_CLASS_AFFINITY_SERVICE = "AfinidadeService";
    public static final String LOG_CLASS_SCORE_SERVICE = "ScoreService";
    public static final String LOG_CLASS_PERSON_SERVICE = "PessoaService";
    public static final String LOG_CLASS_USER_SERVICE = "UsuarioService";


    /**
     * LOG_METHOD
     */
    public static final String LOG_METHOD_FIND_ALL = "findAll";
    public static final String LOG_METHOD_FIND_BY_ID = "findById";
    public static final String LOG_METHOD_FIND_PRODUCTS = "findProducts";
    public static final String LOG_METHOD_FIND_STATE_REGION = "findStatesAffinityByRegion";
    public static final String LOG_METHOD_CREATE = "create";
    public static final String LOG_METHOD_GET_SCORE_DESCRIPTION = "getDescriptionScore";



    /**
     * LOG_MESSAGES
     */
    public static final String LOG_MSG_START_CREATE_AFFINITY = "Início do cadastro de uma afinidade ";
    public static final String LOG_MSG_END_CREATE_AFFINITY = "Fim do cadastro de uma afinidade ";

    public static final String LOG_MSG_START_CREATE_SCORE = "Início do cadastro de um score ";
    public static final String LOG_MSG_END_CREATE_SCORE = "Fim do cadastro de um score ";

    public static final String LOG_MSG_START_CREATE_PERSON = "Início do cadastro de uma pessoa ";
    public static final String LOG_MSG_END_CREATE_PERSON = "Fim do cadastro de uma pessoa ";

    public static final String LOG_MSG_FIND_ALL_PERSON = "Buscando todas as pessoas ";
    public static final String LOG_MSG_FIND_BY_ID_PERSON  = "Buscando uma pessoa por id: ";
    public static final String LOG_MSG_FIND_STATE_REGION = "Buscando estados de affindade por região";
    public static final String LOG_MSG_GET_SCORE_DESCRIPTION = "Buscando a descrição do score";

    public static final String LOG_MSG_START_AUTHENTICATE_USER = "Autenticando o usuário";
    public static final String LOG_MSG_START_REGISTER_USER = "Registrando um novo usuário";

    /**
     * CONSTANTS_FIELDS
     */
    public static final String FIELD_USER_NOT_FOUND = "Usuário com e-mail ";
    public static final String FIELD_NAME = "nome";
    public static final String FIELD_PASSWORD = "senha";
    public static final String FIELD_EMAIL = "e-mail";
    public static final String FIELD_ROLES = "perfil";
    public static final String FIELD_REGION = "região";
    public static final String FIELD_STATES = "estados";
    public static final String FIELD_PHONE = "telefone";
    public static final String FIELD_AGE = "idade";
    public static final String FIELD_CITY = "cidade";
    public static final String FIELD_BEARER = "Bearer ";
    public static final String FIELD_AUTHORITIES = "roles";

    /**
     * CONSTANTS_LENGTH
     */
    public static final String LENGTH_MIN_PASSWORD = "Use 8 caracteres ou mais para sua senha";
    public static final String LENGTH_MIN_SCORE = "O valor mínimo é de 0";
    public static final String LENGTH_MAX_SCORE = "O valor máximo é de 1000";
    public static final String LENGTH_AGE = "O tamanho deve ser entre 0 e 3 caracteres";
    public static final String LENGTH_FIELD = "O tamanho deve ser entre 3 e 120 caracteres";
    public static final String LENGTH_UF = "O tamanho deve ser de somente 2 caracteres";
    public static final String PASSWORD_PATTERN = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#&()–[{}]:;',?/*~$^+=<>]).{8,20}$";
    public static final String POSITIVE_AGE = "O campo idade deve ser um valor positivo";


    /**
     * CONSTANTS_STATUS_CODE_HTTP
     */
    public final static int STATUS_CODE_OK = 200;
    public final static int STATUS_CODE_CREATED = 201;
    public final static int STATUS_CODE_NO_CONTENT = 204;
    public final static int STATUS_CODE_BAD_REQUEST = 400;
    public final static int STATUS_CODE_UNAUTHORIZED = 401;
    public final static int STATUS_CODE_FORBIDDEN = 403;
    public final static int STATUS_CODE_NOT_FOUND = 404;
    public final static int STATUS_CODE_CONFLICT = 409;
    public final static int STATUS_CODE_UNPROCESSABLE_ENTITY = 422;
    public final static int STATUS_CODE_INTERNAL_ERROR_SERVER = 500;


    /**
     * CONSTANTS_SWAGGER
     */

    public static final String USER_TAG_DESCRIPTION = "Realiza operações referente aos usuários na api";

    public static final String USER_TAG_NAME = "Users";
    public static final String HEADER = "header";
    public static final String DESCRIPTION = "accessEverything";
    public static final String SCOPE = "global";
    public static final String FIELD_JWT = "JWT";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String API_RESPONSE_CREATED = "Cadastrado com sucesso!";
    public static final String API_RESPONSE_OK = "Login efetuado com sucesso!";
    public static final String API_RESPONSE_BAD_REQUEST = "Dados não processados devido a solicitação incorreta ou falta de informações.";

    public static final String API_RESPONSE_UNPROCESSABLE_ENTITY = "Os dados não podem ser processados devido a solicitação incorreta.";
    public static final String API_RESPONSE_UNAUTHORIZED = "Acesso não autorizado!";
    public static final String API_RESPONSE_INTERNAL_ERROR_SERVER = "Sistema indisponível";
    public static final String API_RESPONSE_NO_CONTENT = "Sem conteúdo";

    /**
     * CONSTANTS_ERRORS
     */
    public static final String ERROR_NOT_FOUND = "Não encontrado";
    public static final String ERROR_INVALID_EMAIL = "O e-mail informado é inválido";
    public static final String ERROR_VALIDATION = "Erro de validação";
    public static final String ERROR_FORBIDDEN = "Acesso proibido";
    public static final String ERROR_UNAUTHORIZED = "Não autorizado";
    public static final String ERROR_DUPLICATED_EMAIL = "Conflito, o e-mail informado já está em uso";
    public static final String ERROR_INVALID_PROFILE = "Perfil inválido";
    public static final String ERROR_INVALID_PASSWORD = "Senha inválida";
    public static final String ERROR_NO_CONTENT = "Sem conteúdo";

    /**
     * CONSTANTS_MESSAGES
     */
    public static final String MESSAGE_FILL = "O preenchimento do campo ";
    public static final String MESSAGE_REQUIRE = " é obrigatório";
    public static final String MESSAGE_INCORRECT_PASSWORD = "Senha incorreta. Tente novamente ou clique em 'Esqueceu a senha?'";
    public static final String MESSAGE_NOT_FOUND = " não encontrado";

    public static final String MESSAGE_NO_CONTENT = "Nenhum conteúdo para ser visto";
    public static final String MESSAGE_UNAUTHORIZED = "Você não possui credenciais válidas para acessar este recurso";
    public static final String MESSAGE_FORBIDDEN = "Você não possui permissão para acessar este recurso";
    public static final String MESSAGE_INVALID_PROFILE = "O tipo de perfil informado é inválido";

    public static final String MESSAGE_DUPLICATED_EMAIL = "O e-mail informado já está em uso";
    public static final String MESSAGE_INVALID_JWT_SIGNATURE = "Assinatura JWT inválida";
    public static final String MESSAGE_INVALID_JWT_TOKEN = "Token JWT inválido";
    public static final String MESSAGE_EXPIRED_JWT_TOKEN = "Token JWT expirou";
    public static final String MESSAGE_UNSUPPORTED_JWT_TOKEN = "Token JWT não suportado";
    public static final String MESSAGE_EMPTY_JWT_TOKEN = "String JWT está vazia";
    public static final String MESSAGE_INVALID_DATA = "Dados não processados";
    public static final String MESSAGE_VERIFY_REQUEST_DATA = "Os dados não podem ser processados. Verifique sua solicitação";
    public static final String MESSAGE_INVALID_PASSWORD = "Escolha uma senha mais segura. Use uma combinação de letras, números e símbolos.";
    public static final String MESSAGE_INVALID_PASSWORD_CONFIRM_NOT_EQUALS = "As senhas não são iguais. Tente novamente.";
    public static final String MESSAGE_DESABLED_ACCOUNT = "Sua conta está desativada!";

}