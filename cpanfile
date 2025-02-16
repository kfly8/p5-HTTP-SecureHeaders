requires 'perl', '5.008001';

on 'test' => sub {
    requires 'Test2::V0' => '0.000147';
};

on configure => sub {
    requires 'Module::Build::Tiny', '0.035';
};

