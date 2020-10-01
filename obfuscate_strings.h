#pragma once
#include <vector>
namespace cptime
{
	template <std::size_t N, char KEY>
	class obfuscator
	{
	public:

		constexpr obfuscator(const char* data)
		{
			static_assert(KEY != '\0', "KEY must not be the null character.");

			for (std::size_t i = 0; i < N; i++)
			{
				m_data[i] = data[i] ^ KEY;
			}
		}

		constexpr const char* getData() const
		{
			return &m_data[0];
		}

		constexpr std::size_t getSize() const
		{
			return N;
		}

		constexpr char getKey() const
		{
			return KEY;
		}

	private:

		char m_data[N]{};
	};

	template <std::size_t N, char KEY>
	class obfuscated_data
	{
	public:
		obfuscated_data(const obfuscator<N, KEY>& obfuscator)
		{
			for (int i = 0; i < N; i++)
			{
				m_data[i] = obfuscator.getData()[i];
			}
		}

		~obfuscated_data()
		{

			for (int i = 0; i < N; i++)
			{
				m_data[i] = 0;
			}
		}

		// implicit char convertion support
		operator char* ()
		{
			decrypt();
			return m_data;
		}

		void decrypt()
		{
			if (is_encrypted())
			{
				for (std::size_t i = 0; i < N; i++)
				{
					m_data[i] ^= KEY;
				}
			}
		}

		void encrypt()
		{
			if (!is_encrypted())
			{
				for (std::size_t i = 0; i < N; i++)
				{
					m_data[i] ^= KEY;
				}
			}
		}

		bool is_encrypted() const
		{
			return m_data[N - 1] != '\0';
		}

	private:

		char m_data[N];
	};

	// extract the number of elements 'N' in the array 'data'
	template <std::size_t N, char KEY = '.'>
	constexpr auto make_obfuscator(const char(&data)[N])
	{
		return obfuscator<N, KEY>(data);
	}
}

#define cptime_obf(data) cptime_obf_key(data, 'f')

// Obfuscates the string 'data' with 'key' at compile-time and returns a
// reference to a cptime::obfuscated_data object
#define cptime_obf_key(data, key) \
	[]() -> cptime::obfuscated_data<sizeof(data)/sizeof(data[0]), key>& { \
		constexpr auto n = sizeof(data)/sizeof(data[0]); \
		static_assert(data[n - 1] == '\0', "String must be null terminated"); \
		constexpr auto obfuscator = cptime::make_obfuscator<n, key>(data); \
		static auto obfuscated_data = cptime::obfuscated_data<n, key>(obfuscator); \
		return obfuscated_data; \
	}()
