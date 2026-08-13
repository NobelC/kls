#pragma once
#include <variant>

namespace kls {   
  template <typename T>
    struct Success{
      T value;
    };

  template <typename E>
    struct Failure{
      E error;
    };

  template <typename T, typename E>
    using Result = std::variant<Success<T>, Failure<E>>;
}
