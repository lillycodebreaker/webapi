using AutoMapper;
using DataAccess.EntityDBCalls;
using DataAccess.Framework;
using Microsoft.AspNetCore.Mvc;
using System;
using Microsoft.Extensions.Configuration;

namespace webapi.Controllers
{
	[Produces("application/json")]
	[ApiController]
	public abstract class BaseController : Controller
    {
    		private readonly ListDbCall dbCall;
		private readonly LoggerDbCall loggerDbCall;
		private readonly AuditDbCall auditDbCall;
		private readonly IMapper mapper;
		private readonly IConfiguration _configuration;
		private readonly string requestUser;
		public BaseController(IDbConnection dbConnection, IMapper mapper, IConfiguration configuration)
		{
			if (dbConnection == null)
			{
				throw new ArgumentNullException(nameof(dbConnection));
			}
			dbCall = new FeeSchedueDetailDbCall(dbConnection);
			loggerDbCall = new LoggerDbCall(dbConnection);
			auditDbCall = new AuditDbCall(dbConnection);
			this.mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
			_configuration = configuration;
			Request.Headers.TryGetValue("Request_UserName", out var requestUser);
		}		
    }
}
