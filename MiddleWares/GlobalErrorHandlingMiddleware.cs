using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text.Json;

namespace RefreshToken.MiddleWares
{
    public class GlobalErrorHandlingMiddleware
    {
        private readonly ILogger<GlobalErrorHandlingMiddleware> _logger;
        private readonly RequestDelegate _requestDelegate;

        public GlobalErrorHandlingMiddleware(ILogger<GlobalErrorHandlingMiddleware> logger, RequestDelegate requestDelegate)
        {
            _logger = logger;
            _requestDelegate = requestDelegate;
        }

        public async Task Handle(HttpContext context)
        {
            try
            {
                _logger.LogInformation("A request has Come in");
                await _requestDelegate(context);
                _logger.LogInformation("The request has completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,ex.Message);

                var detail = new ProblemDetails()
                {
                    Detail = "Internal Server Error",
                    Instance = "Error",
                    Status = 500,
                    Title = "Server Error",
                    Type = "Error",
                };

                var response = JsonSerializer.Serialize(detail);
                context.Response.StatusCode = (int) HttpStatusCode.InternalServerError;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(response);

            }
        }
    }
}
