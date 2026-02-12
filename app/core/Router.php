<?php

class Router
{
    private array $routes = [];//Routes Storage

    public function add(string $method, string $path, callable $handler)
    {
        // Convert /api/patients/{id} → regex
        $paramNames = [];

        $regex = preg_replace_callback(
            '/\{([^}]+)\}/',
            
            //callback to capture param name and store in $paramNames
            function ($matches) use (&$paramNames) {
                $paramNames[] = $matches[1];
                return '([^/]+)';
            },
            $path
        );

        $regex = '#^' . $regex . '$#';

        $this->routes[] = [
            'method'     => $method,
            'path'       => $path,
            'regex'      => $regex,
            'params'     => $paramNames,
            'handler'    => $handler
        ];
    }

    public function dispatch(string $requestUri, string $requestMethod)
    {
        $requestUri = parse_url($requestUri, PHP_URL_PATH);

        // Remove project folder (important for localhost)
        $basePath = '/project';
        if (strpos($requestUri, $basePath) === 0) {
            $requestUri = substr($requestUri, strlen($basePath));
        }

        foreach ($this->routes as $route) {
            if ($route['method'] !== $requestMethod) {
                continue;
            }

            if (preg_match($route['regex'], $requestUri, $matches)) {
                array_shift($matches); // full match
                $params = array_combine($route['params'], $matches);

                call_user_func($route['handler'], $params);
                return;
            }
        }

        http_response_code(404);
        echo json_encode([
            "status" => false,
            "message" => "Route not found"
        ]);
    }
}
