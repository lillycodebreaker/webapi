using AutoMapper;
using DataAccess.Framework;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using System.Data.SqlClient;
using System.Threading.Tasks;
using Kong.Authentication.StarGateJWT.lib;
using Kong.Authentication.StarGateJWT.lib.Events;

namespace ProsExari
{
	public class Startup
	{
		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
		}

		public IConfiguration Configuration { get; }

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			services.AddAutoMapper(typeof(Startup));

			services.AddCors(options =>
			{
				options.AddPolicy("CorsPolicy",
					/************************************************/
					/* THIS NEEDS TO BE SET FOR THE UI SPECIFICALLY
					 * IT SHOULD NOT ALLOW ALL */
					/*************************************************/
					builder => builder
						.AllowAnyOrigin()
						.AllowAnyMethod()
						.AllowAnyHeader()
						.AllowCredentials());
			});

			services.AddMvc()
				.SetCompatibilityVersion(CompatibilityVersion.Version_2_1)
				.AddJsonOptions(options =>
				{
					options.SerializerSettings.Formatting = Formatting.Indented;
				});

			services.AddScoped<IMSPFSDbConnection>(s => new MSPFSDbConnection(new SqlConnection(Configuration.GetConnectionString("MSPSEntities_ProsExari_Core"))));

			services.AddScoped<IFRSDbConnection>(s => new FRSDbConnection(new SqlConnection(Configuration.GetConnectionString("FRS_ProsExari_Core"))));

			services.AddSwaggerGen(c =>
			{
				c.SwaggerDoc("v1", new OpenApiInfo { Title = "ProsExari API Docs", Version = "v1", Description = "ProsExari V1 Resource API, provides MSPS payment appendix file and schedule information", TermsOfService = new System.Uri("https://www.optumdeveloper.com/content/odv-optumdev/optum-developer/en/legal-terms/terms-of-use.html"), Contact = new OpenApiContact() { Name = "ProsExari", Email = "PROS_DSETeam_DL@ds.uhc.com" }});
			});
			
			services.AddAuthentication(Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme);

			//services.AddAuthentication(JwtDefaults.AuthenticationScheme)
			// .AddJwt(cfg =>
			// {
			//	 //cfg.RequireHttpsMetadata = false;
			//	 cfg.SaveToken = true;
			//	 cfg.Events = new JwtEvents
			//	 {
			//		 OnTokenValidated = context => Task.CompletedTask
			//	 };
			// });

			services.Configure<IISOptions>(options =>
			{
				options.AutomaticAuthentication = true;
				options.ForwardClientCertificate = true;
			});

		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IHostingEnvironment env)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
			}
			else
			{
				app.UseHsts();
			}

			app.UseSwagger();

			app.UseSwaggerUI(c =>
			{
				c.SwaggerEndpoint("swagger/v1/swagger.json", "ProsExari API V1");
				c.RoutePrefix = string.Empty;
			});

			app.UseCors("CorsPolicy");
			app.UseAuthentication();
			app.UseMvc();
		}
	}
}
