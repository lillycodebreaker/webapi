using Dapper;
using DataAccess.Entities;
using DataAccess.Framework;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;

namespace DataAccess.EntityDBCalls
{
	public class ListDbCall
	{
		private readonly IDbConnection dbConnection;
		

		public ListDbCall(IDbConnection dbConnection)
		{
			this.dbConnection = dbConnection ?? throw new ArgumentNullException(nameof(dbConnection));
		}

		public IEnumerable<MKT> GetMarkets()
		{
			return mspfsConnection.DbConnection.Query<MKT>("usp_API_GetMarketList", commandType: CommandType.StoredProcedure).Where((m) => !string.IsNullOrEmpty(m.MKT_NAME));
		}
	}
}
