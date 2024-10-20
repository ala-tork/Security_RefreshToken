using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text.Json;

namespace RefreshToken.MiddleWares
{
    public class GlobalHandlingErrorMid : IMiddleware
    {
        private readonly ILogger<GlobalErrorHandlingMiddleware> _logger;
        public GlobalHandlingErrorMid(ILogger<GlobalErrorHandlingMiddleware> logger)
        {
            _logger = logger;
        }
        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            try
            {
                _logger.LogInformation("A request has Come in");
                await next(context);
                _logger.LogInformation("The request has completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);

                var detail = new ProblemDetails()
                {
                    Detail = "Internal Server Error",
                    Instance = "Error",
                    Status = 500,
                    Title = "Server Error",
                    Type = "Error",
                };

                var response = JsonSerializer.Serialize(detail);
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(response);
            }
        }
    }
}
