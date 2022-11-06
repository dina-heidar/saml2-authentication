using FluentValidation;
using MediatR;
using MetadataBuilder.Schema.Metadata;
using Microsoft.IdentityModel.Xml;
using Saml.MetadataBuilder;
using System.Xml;
using System.Xml.Serialization;

namespace MvcClient.Features.Metadata;

public class Create
{
    public class Command : IRequest<XmlDocument>
    {
        public BasicSpMetadata ServiceProviderMetadata { get; set; }
    }

    public class CommandValidator : AbstractValidator<Command>
    {

    }

    public class Handler : IRequestHandler<Command, XmlDocument>
    {
        private readonly IMetadataWriter _writer;
        private readonly IMetadataReader _reader;
        public Handler(IMetadataWriter writer, IMetadataReader reader)
        {
            _writer = writer;
            _reader = reader;
        }

        /// <summary>
        /// Handles the specified command.
        /// </summary>
        /// <param name="command">The command.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public async Task<XmlDocument> Handle(Command command,
            CancellationToken cancellationToken = default)
        {
            var sp = command.ServiceProviderMetadata;

            var metadataAddress = "https://adfs.la.gov/federationmetadata/2007-06/federationmetadata.xml";
            var entityDescriptor = await _reader.Read(metadataAddress, cancellationToken);

            var xml = _writer.Output(sp);
            return xml;
        }
    }
}

