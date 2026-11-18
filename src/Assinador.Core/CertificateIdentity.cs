// SPDX-License-Identifier: AGPL-3.0-only
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Jhonju.Assinador.Core;

public sealed record CertificateIdentity(string Name, string Document)
{
    public static CertificateIdentity From(X509Certificate2 certificate)
    {
        var name = certificate.GetNameInfo(X509NameType.SimpleName, false);
        var otherNames = new Dictionary<string, string>();
        var alternative = certificate.Extensions["2.5.29.17"];
        if (alternative is not null)
        {
            var names = new AsnReader(alternative.RawData, AsnEncodingRules.DER).ReadSequence();
            while (names.HasData)
            {
                if (names.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    var other = names.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                    var oid = other.ReadObjectIdentifier();
                    var value = other.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                    otherNames[oid] = ReadText(value.ReadEncodedValue());
                }
                else names.ReadEncodedValue();
            }
        }
        otherNames.TryGetValue("2.16.76.1.3.3", out var cnpj);
        otherNames.TryGetValue("2.16.76.1.3.1", out var person);
        var cpf = person is { Length: >= 19 } ? person.Substring(8, 11) : null;
        cpf = IsDigits(cpf, 11) ? cpf : ReadSubjectAttribute(certificate, "2.5.4.5");
        cpf = IsDigits(cpf, 11) ? cpf : Regex.Match(name, @":(\d{11})$").Groups[1].Value;
        var document = IsDigits(cnpj, 14)
            ? $"CNPJ: {cnpj![..2]}.{cnpj[2..5]}.{cnpj[5..8]}/{cnpj[8..12]}-{cnpj[12..]}"
            : IsDigits(cpf, 11)
                ? $"CPF: {cpf![..3]}.{cpf[3..6]}.{cpf[6..9]}-{cpf[9..]}"
                : "Identificação conforme certificado digital";
        return new(Regex.Replace(name, @":\d{11,14}$", ""), document);
    }

    private static bool IsDigits(string? value, int length) =>
        value?.Length == length && value.All(c => c is >= '0' and <= '9');

    private static string? ReadSubjectAttribute(X509Certificate2 certificate, string oid)
    {
        var subject = new AsnReader(certificate.SubjectName.RawData, AsnEncodingRules.DER).ReadSequence();
        while (subject.HasData)
        {
            var set = subject.ReadSetOf();
            while (set.HasData)
            {
                var attribute = set.ReadSequence();
                var key = attribute.ReadObjectIdentifier();
                var text = ReadText(attribute.ReadEncodedValue());
                if (key == oid) return text;
            }
        }
        return null;
    }

    private static string ReadText(ReadOnlyMemory<byte> encoded)
    {
        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        var tag = reader.PeekTag();
        if (tag.TagClass == TagClass.ContextSpecific && tag.IsConstructed)
            return ReadText(reader.ReadSequence(tag).ReadEncodedValue());
        if (tag.TagClass != TagClass.Universal) return "";
        return (UniversalTagNumber)tag.TagValue switch
        {
            UniversalTagNumber.UTF8String or UniversalTagNumber.PrintableString or
            UniversalTagNumber.IA5String or UniversalTagNumber.NumericString or UniversalTagNumber.BMPString
                => reader.ReadCharacterString((UniversalTagNumber)tag.TagValue),
            UniversalTagNumber.OctetString => Encoding.UTF8.GetString(reader.ReadOctetString()),
            _ => ""
        };
    }
}
