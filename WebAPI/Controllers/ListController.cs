using AutoMapper;
using DataAccess.EntityDBCalls;
using DataAccess.Framework;
using Microsoft.AspNetCore.Mvc;
using WebAPI.DTOs;
using System;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;

namespace WebAPI.Controllers
{
	[Produces("application/json")]
	[ApiController]
	public class ListController : Controller
	{
		private readonly ListDbCall listDbCall;
		private readonly LoggerDbCall loggerDbCall;
		private readonly AuditDbCall auditDbCall;
		private readonly IMapper mapper;
		private readonly IConfiguration _configuration;
		public ListController(IDbConnection dbConnection, IMapper mapper, IConfiguration configuration)
		{
			if (dbConnection == null)
			{
				throw new ArgumentNullException(nameof(dbConnection));
			}
			listDbCall = new ListDbCall(dbConnection);
			loggerDbCall = new LoggerDbCall(dbConnection);
			auditDbCall = new AuditDbCall(dbConnection);
			this.mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
			_configuration = configuration;
		}

		[Route("/v1/markets-lists")]
		[HttpGet]
		public ActionResult<List<MarketObject>> GetMarkets()
		{
			string controllerName = this.ControllerContext.RouteData.Values["controller"].ToString();
			string actionName = this.ControllerContext.RouteData.Values["action"].ToString();
			string requestUser = "";
			Microsoft.Extensions.Primitives.StringValues requestUsers;
			if (Request.Headers.TryGetValue("Requestor-Username", out requestUsers))
			{
				requestUser = requestUsers[0].ToString();
			}

			try
			{
				string auditExclusion = _configuration["AuditSettings:Exclusion"];
				auditDbCall.AuditSimple(requestUser, controllerName + "/" + actionName, auditExclusion.Split(","));
				return mapper.Map<List<MarketObject>>(listDbCall.GetMarkets());
			}
			catch (Exception ex)
			{
				loggerDbCall.LogError(ex.Message, ex.StackTrace, controllerName + "/" + actionName);
				throw ex;
			}
		}
	}
}