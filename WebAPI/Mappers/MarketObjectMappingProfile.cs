using AutoMapper;
using DataAccess.Entities;
using WebAPI.DTOs;

namespace WebAPI.Mappers
{
	public class MarketObjectMappingProfile : Profile
	{
		public MarketObjectMappingProfile()
		{
			CreateMap<MKT, MarketObject>()
				.ForMember(dest => dest.MarketName, opt => opt.MapFrom(src => src.MKT_NAME));
		}
	}
}
